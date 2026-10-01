# Armory → Rust: feature evaluation against the current contract

Status: v0.1 delivered (see §7 for what shipped and what is deferred) · Date: 2026-10-01 · Branch: `rust-rebuild`

## 0. Scope and interpretation

**"Current contract"** is read here as: *the Bitcoin consensus and policy rules in force today, together with the
public interfaces of current Bitcoin Core (v29–v31)*. A legacy feature is "still available" if it can work
correctly against those, either unchanged or with a redesigned implementation. Features that depended on
services run by Armory Technologies, Inc. (ATI) are judged against what is actually reachable today.

**Target**: a Rust rebuild for Fedora Linux and macOS (x86_64 + arm64) with a complete CLI and a TUI in place of
the PyQt4 GUI. Windows-only code (NSIS installer, py2exe, `subprocess_win.py`, registry URI handler) is out of
scope.

**Evidence** for every verdict lives in the specs in `specs/` (each claim there cites `file:line` in this tree):

| Spec | Topic | How it was verified |
|---|---|---|
| [01](specs/01-wallet-format-and-crypto.md) | `.wallet` v1.35 format, KDF, AES-CFB, legacy key chain | Parsed all 3 fixture wallets; 50 chained addresses per wallet re-derived; KDF/AES/chain checked against the original C++ (see `tools/legacy-oracle/`) |
| [02](specs/02-backups-and-recovery.md) | Easy16 paper backup, SecurePrint, Shamir fragments, recovery tool | Python 3 port passes 217/217 checks against every vector in `pytest/` |
| [03](specs/03-transactions-and-signing.md) | USTX/TxSigCollect, signing, fees, coin selection, signed messages | All fixture/test USTX IDs recompute; every stored signature verifies |
| [04](specs/04-lockboxes-multisig.md) | Lockboxes, public-key blocks, promissory notes, simulfunding | All 8 fixture files decode; all IDs recompute |
| [05](specs/05-blockchain-backend-and-network.md) | BDM, LMDB, P2P, RPC, SDM, dead URLs; Core v31 interfaces | Core source + release notes up to v31.1 |
| [06](specs/06-feature-inventory.md) | 394-row inventory of every user-facing feature | Source read |
| [07](specs/07-upstream-open-issues.md) | Triage of the upstream project's open issues | Public issue pages |

Python 2 is not available on current Fedora/macOS, so the old test suite cannot run. Byte-compatibility instead
rests on (a) hard-coded vectors in `pytest/`, (b) golden fixtures copied to `fixtures/legacy/`, and (c) a harness
that compiles Armory's original C++ crypto (`tools/legacy-oracle/`).

## 1. Verdict summary

| Bucket | Meaning | Headline items |
|---|---|---|
| **A. Keep** | Valid against today's contract; port faithfully, byte-compatible | v1.35 wallet file read/write, ROMix KDF, AES-256-CFB, legacy key chain, paper backups (Easy16, SecurePrint), Shamir fragmented backups, lockbox/promissory-note/USTX formats (as *import/export*), Bitcoin signed messages, P2PKH/P2SH/bare-multisig signing, low-S, address book, comments, CSV export, coin control |
| **B. Keep, redesign** | The feature is still wanted, but the old mechanism is broken or obsolete | Blockchain data (C++ BDM → Bitcoin Core RPC), fees (`estimatefee`/priority → `estimatesmartfee`, sat/vB), broadcast (P2P → `testmempoolaccept` + `sendrawtransaction`), offline-signing interchange (USTX → PSBT primary, USTX kept), networks (`--testnet` → mainnet/testnet4/signet/regtest), RPC auth (`rpcuser` → cookie), node management (launch bitcoind → detect only), GUI → CLI/TUI, printing (QPrinter → text/PDF/terminal), notifications, daemon RPC |
| **C. Drop** | Depends on dead infrastructure or obsolete design | ATI announcements/version check/secure downloader/`versions.txt`, torrent bootstrap, bitcoind auto-download, bug-report upload, SMTP email from armoryd, ATI-signed plugin zips, donation nags, Windows packaging, Bitcoin alert system, `TxDP` format (already unparseable in 0.93) |
| **D. New (forced by the contract)** | Not in Armory, but required to be usable today | Pay to bech32/bech32m (P2WPKH, P2WSH, P2TR) addresses, BIP144 tx parsing, vbyte fee maths, RBF awareness, PSBT (BIP174), descriptor export, testnet4/signet, Core ≥ 29 cookie-auth, segwit receive addresses for **new** wallets (see decision D-1) |

## 2. Decisions (D-1 and D-2 decided; the rest proceed on their recommended defaults)

These are deliberately **not** decided silently. Each has a recommended default which the architecture plan
(`01-architecture.md`) assumes until told otherwise.

| ID | Question | Options | Recommendation |
|---|---|---|---|
| **D-1** | What key scheme do *new* wallets use? | (a) Legacy 1.35 only · (b) BIP32 (BIP84 + BIP86) · (c) both | **Decided (owner, 2026-10-01): modern.** New wallets are BIP39/BIP32 with a BIP84 account (BIP86 optional) in the v2 format ([ADR-002](02-modern-wallet-format.md)). v1.35 wallets are migrated into a `legacy-1.35` account; `armory legacy …` keeps byte-compatible access. |
| **D-2** | How do new BIP32 wallets get backed up? | (a) BIP39 · (b) Easy16 paper of the seed (+ SecurePrint) · (c) Shamir fragments of the seed · (d) SLIP-39 | **Decided with D-1:** 24 BIP39 words, plus Armory paper/SecurePrint/fragment formats applied to the BIP39 entropy (fragments with random coefficients). |
| **D-3** | Offline-signing interchange | (a) Legacy USTX only · (b) PSBT only · (c) PSBT primary, USTX import/export for legacy offline signers | **(c)**. USTX cannot carry segwit inputs; PSBT is what every other signer speaks. |
| **D-4** | Backend scope for v1 | (a) Bitcoin Core RPC only · (b) Core + Electrum server | **(a)** for v1 behind a `ChainBackend` trait; Electrum in v2 (it helps pruned-node users restore old backups). |
| **D-5** | Keep an `armoryd`-compatible JSON-RPC daemon? | (a) Yes, method-compatible · (b) New JSON-RPC API mirroring the CLI · (c) No daemon | **(b)** in a later phase, with a shim that keeps the method names that still make sense (§4.12). The CLI ships first. |
| **D-6** | Deterministic signatures | (a) Reproduce Armory's non-standard RFC 6979 variant bit-for-bit · (b) Standard RFC 6979 (libsecp256k1) | **(b)**. Both produce valid signatures; nothing depends on byte-identical signatures. Armory's variant is kept as a test-only function for checking fixtures. |

## 3. Cross-cutting findings that shape the design

1. **The block indexer cannot be salvaged.** The C++ tx parser has no BIP144 support, so every mainnet block since
   height 481,824 (Aug 2017) fails its merkle check. Core ≥ 28 also XOR-obfuscates `blk*.dat` (`xor.dat`), so
   Armory finds zero blocks on a fresh node. Pruned nodes are refused. → Replace with Core RPC. ([05 §2.1–2.3](specs/05-blockchain-backend-and-network.md))
2. **Core removed every RPC Armory called** (`getinfo` 0.16, `estimatefee` 0.17, `estimatepriority` 0.15), and
   Core 30 removed legacy wallets (`importaddress`/`importpubkey`). Watching Armory addresses therefore requires
   **descriptor watch-only wallets** with one `pkh(<pubkey>)` or `sh(multi(...))` descriptor per address.
   ([05 §4.2](specs/05-blockchain-backend-and-network.md))
3. **Armory 1.x keys are not BIP32.** The chain is `priv[n+1] = priv[n] · H256(pub[n]) ⊕ chaincode (mod n)`, with
   uncompressed keys and a non-standard HMAC (32-byte block) for chain-code derivation. No xpub or ranged descriptor
   can describe it, so lookahead is computed locally and imported in batches. ([01 §5](specs/01-wallet-format-and-crypto.md))
4. **The legacy formats have undocumented variants.** There are three USTX layouts, all labelled version 1; lockbox
   version 0; promissory notes with version 0 in a v1 layout; ASCII armour at 64 vs 80 columns with CRLF; and no
   block-type check on import. Readers must be tolerant and must be tested on every fixture. Writers must emit the
   newest layout. ([03](specs/03-transactions-and-signing.md), [04](specs/04-lockboxes-multisig.md))
5. **Several legacy behaviours are bugs and must not be ported:**
   - non-zero `nLockTime` silently written as 0;
   - armoryd `sendtransaction` never broadcasts;
   - GUI broadcasts multisig spends even when signature verification fails;
   - the recovery tool's damaged-entry repair cannot work as written;
   - compressed imported keys printed with SecurePrint appear unrestorable;
   - coin selection uses randomness and has several bugs.

   Each one is listed with its reference in the specs' quirk lists.
6. **Fragmented backups have a known flaw that must not be carried forward.** `SplitSecret` derives every polynomial
   coefficient from an HMAC chain of the secret (`armoryengine/ArmoryUtils.py:2595-2601`), and x-coordinates are
   always 1..N. Fragment sets made with *different* M for the same wallet therefore share coefficients: for example,
   two fragments of a 3-of-N set plus one fragment of a 2-of-N set give three equations in the three unknowns, so the
   wallet can be recovered. The successor project (goatpig 0.96.3) fixed this as a vulnerability. The rebuild
   **restores** legacy deterministic fragments, but **creates** new sets with CSPRNG coefficients and a random set
   ID, and refuses to mix sets. ([07 §3 P0-1](specs/07-upstream-open-issues.md), [02 §4](specs/02-backups-and-recovery.md))
7. **Privacy regressions to remove**: the announce fetch and bug-report upload sent identifying data to ATI
   endpoints; the internet probe hit Google. Nothing in the rebuild phones home. ([05 §3](specs/05-blockchain-backend-and-network.md))

## 4. Parity map (every user-facing feature → verdict → CLI/TUI surface)

Row IDs are the stable IDs from [06-feature-inventory](specs/06-feature-inventory.md). **Verdicts**: A = keep,
B = keep/redesign, C = drop, M = merged into another row. The **CLI** column is the `armory` subcommand that delivers the
feature. The TUI exposes the same operations through screens (§5). Parity is reached when every A/B row has a passing
integration test for its CLI command.

### 4.1 Wallet management

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| WM-01 | Wallet list | A | `armory wallet list` (TUI: Wallets screen) |
| WM-02 | Per-wallet ledger visibility | B | `armory config set wallet.<id>.ledger-show` (TUI toggle) |
| WM-03 | Create wallet wizard | B | `armory wallet create [--type bip84\|legacy] [--label] [--no-encrypt]` (see D-1) |
| WM-04 | Supplemental entropy | A | `armory wallet create --extra-entropy` (prompted, mixed into OS RNG) |
| WM-05 | Wallet properties | A | `armory wallet show <id>` |
| WM-06 | Change labels | A | `armory wallet rename <id> --label --description` |
| WM-07 | Set/change/remove passphrase | A | `armory wallet passphrase <id> {set,change,remove}`; KDF recalibrated per spec 01 §3 |
| WM-08 | Unlock prompt | B | Per-command passphrase prompt (no persistent unlock in the CLI); `armory daemon` keeps an unlock timeout |
| WM-09 | Auto-lock after timeout | B | Daemon/TUI only: zeroize keys after the timeout |
| WM-10 | Delete wallet | A | `armory wallet delete <id> [--watch-only-keep]` (asks for confirmation and offers a backup) |
| WM-11 | Set owner ("belongs to") | A | `armory wallet set-owner <id> {mine,other --name}` |
| WM-12 | Extend address pool | A | `armory wallet extend-pool <id> <n>` (also imports descriptors to the backend) |
| WM-13 | Test KDF time | A | `armory wallet kdf-info <id> [--benchmark]` |
| WM-14/15 | Import or restore wallet / import wallet file | A | `armory wallet import <file.wallet>` (v1.35, incl. watching-only) |
| WM-16 | Replace/merge on restore | A | `armory wallet import --replace\|--merge` |
| WM-17 | Fix damaged wallet | A | `armory wallet recover <file> --mode {full,stripped,bare,meta}`; do not port the broken repair path |
| WM-18 | Startup consistency check | A | Automatic on load + `armory wallet check <id>` |
| WM-19 | Negative-import report | M | Part of `wallet check` |
| WM-20 | Duplicate wallet resolution | A | Load refuses duplicates with a clear message; `wallet import` detects them |
| WM-21 | Registration & scan | B | `armory wallet sync <id>` (imports descriptors to Core, rescans from birthday) |
| WM-22 | Wallet type (full/WO/offline) | A | Shown in `wallet list/show` |
| WM-23 | Ledger filter by group | B | `armory history --filter {mine,offline,others,all}` |
| WM-24 | Total balance | A | `armory balance [--wallet]` |
| WM-25 | Watching-only support | A | First-class; `wallet export-watchonly` |
| WM-26/27 | Address table / context menu | A | `armory address list <id> [--used\|--unused\|--change]`, plus `address show/label/keys` |
| WM-28 | Address comments | A | `armory address label <addr> <text>` |

### 4.2 Addresses / receiving

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| AR-01 | New receive address | A | `armory address new <wallet>` (D-1: segwit for BIP84 wallets) |
| AR-02 | Receive warnings | B | Warn when the wallet has no backup (`--i-have-a-backup` to silence) |
| AR-03 | `bitcoin:` URI | A | `armory uri create <addr> [--amount --label --message]` / `armory uri parse <uri>` (BIP21) |
| AR-04 | QR code | B | `armory address qr <addr\|uri>` renders a Unicode QR in the terminal; `--png` writes a file |
| AR-05 | Address info | A | `armory address show <addr>` (balance, tx count, wallet, index) |
| AR-06 | View keys | A | `armory address keys <addr> [--wif\|--hex\|--pubkey]` (passphrase required, shows a warning) |
| AR-07 | Import private key | A | `armory address import-key <wallet> [--file]` (WIF, hex, mini key; see spec 01 §10) |
| AR-08 | Sweep private key | B | `armory sweep <key> --to <wallet>` (uses `scantxoutset`, so no wallet import or rescan is needed) |
| AR-09 | Remove imported address | A | `armory address remove-imported <addr>` |
| AR-10 | Address book | A | `armory addressbook {list,add,remove}` (sent-to history plus manual entries) |
| AR-11 | Recipient parsing | D | Accepts base58 P2PKH/P2SH, **bech32/bech32m**, lockbox refs, URIs |
| AR-12/13 | Script display / live identification | A | Shared formatting library used by CLI and TUI |
| AR-14 | Next-unused semantics | A | Kept exactly (spec 01 §6) |

### 4.3 Sending

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| SD-01/02 | Send with multiple recipients | A | `armory send <wallet> --to <addr>=<amt> [--to ...]`; `--max` sends everything |
| SD-03 | Fee | B | `--fee-rate <sat/vB>` or `--target <blocks>` (`estimatesmartfee`); floor at relay fee; the old flat fee/priority logic is dropped |
| SD-04 | Coin control | A | `--from-utxo <txid:vout>...` / `--from-address`; `armory utxo list` |
| SD-05 | Change behaviour | A | `--change {new,reuse,addr:<a>}`, plus the per-wallet default in config |
| SD-06 | Confirm | A | Summary plus a y/N prompt (`--yes` for scripts) |
| SD-07 | Create unsigned instead | B | `--unsigned-out <file> [--format psbt\|ustx]` |
| SD-08 | Sign & broadcast | B | `testmempoolaccept`, then `sendrawtransaction`; Core's reject reason is shown verbatim |
| SD-09 | Pay a URI | A | `armory send --uri <bitcoin:...>` |
| SD-10 | Donation prompt | C | Dropped |
| SD-11 | Spend zero-conf rules | A | Only own-change zero-conf is spendable by default (`--allow-unconfirmed`) |
| SD-12 | Send to lockbox / P2SH / pubkey / bare multisig | A | `--to lockbox:<id>=<amt>` etc. |
| SD-13 | Tx comment | A | `--comment`, `armory tx comment <txid> <text>` |
| — | RBF / CPFP | D | `--rbf` (default on), `armory tx bump-fee <txid>` (new) |

### 4.4 Offline signing

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| OS-01 | Offline hub | B | `armory offline` group (TUI: Offline screen) |
| OS-02 | v0.92 format warning | M | Reader accepts all USTX layouts silently (finding 4) |
| OS-03 | Review/export unsigned | A | `armory tx show <file>` (PSBT or USTX); `armory tx convert --to {psbt,ustx}` |
| OS-04 | Sign / broadcast offline tx | A | `armory tx sign <file> --wallet <id> [-o out]`, `armory tx broadcast <file>` |
| OS-05 | Tx details viewer | A | `armory tx show <txid\|file> [--verbose]` |
| OS-06 | Offline mode | B | `--offline` / `network.backend = "none"`: everything except sync/broadcast works with no node |
| OS-07 | `cli_sign_txdp.py` (TxDP) | C | TxDP is already unreadable in 0.93; superseded by `armory tx sign` |
| OS-08 | Offline wizard (dormant) | C | Never shipped |

### 4.5 Backups

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| BK-01/02 | Backup chooser | A | `armory backup <wallet>` (interactive menu in the TUI) |
| BK-03 | Single-sheet paper backup | B | `armory backup paper <wallet> [--secureprint] [--format text\|pdf\|html]`: no QPrinter; outputs printable text/PDF |
| BK-04 | Fragmented M-of-N backup | B | `armory backup fragments <wallet> -m M -n N [--secureprint] [--format ...]`; Expert limits (8/12) apply everywhere |
| BK-05 | Digital backup | A | `armory backup file <wallet> <dest>` (atomic copy, 0600) |
| BK-06 | Export key list | A | `armory wallet export-keys <wallet> [--format csv\|text]` (with warning) |
| BK-07 | Export watching-only | A | `armory wallet export-watchonly <wallet> [--root-data]` |
| BK-08 | Restore single sheet | A | `armory restore paper` (prompts line by line with per-line checksum repair, version 1.35a/1.35c, SecurePrint code) |
| BK-09 | Restore fragments | A | `armory restore fragments` (any M fragments, set-ID check) |
| BK-10 | Restore WO from root data | A | `armory restore watchonly` |
| BK-11 | Test my backup | A | `armory backup test <wallet>` (restores in memory and compares the wallet ID) |
| BK-12 | Legacy paper dialog (dormant) | M | Covered by BK-08 |
| BK-13 | `frag_wallet.py`/`unfrag_wallet.py` | M | Covered by BK-04/BK-09 |

### 4.6 Multisig / lockboxes

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| MS-01..03 | Lockbox manager & actions | A | `armory lockbox {list,show}` (TUI: Lockboxes screen) |
| MS-04 | Create/edit lockbox | A | `armory lockbox create -m M --key <pubkey-block\|hex>... [--name --description]` |
| MS-05 | Select pubkey | A | `armory lockbox export-key <wallet>` (writes a public-key block) |
| MS-06/07/08 | Export/import lockbox, generic ASCII import | A | `armory lockbox export <id>`, `armory import <file>` (auto-detects the block type; fixes the missing type check) |
| MS-09 | Fund lockbox | A | `armory send --to lockbox:<id>=<amt>` |
| MS-10 | Spend from lockbox | B | `armory lockbox spend <id> --to ... -o <file>` (PSBT or USTX) |
| MS-11 | Collect/merge signatures | B | `armory tx sign` + `armory tx merge <f1> <f2>...`; **verify every signature before broadcast** (the GUI didn't) |
| MS-12..14 | Simulfunding & promissory notes | A | `armory promnote {create,merge}` |
| MS-15 | Persistence & registration | B | `lockboxes.toml` (+ read `multisigs.txt`); `sh(multi())` descriptor imported to Core |
| MS-16 | Lockbox reference syntax | A | `lockbox:<id>` / `Lockbox[Bare:<id>]` accepted everywhere |
| MS-17 | Ledger lockbox column | A | `armory history --lockbox <id>` |
| — | P2WSH / native multisig | D | Future: `wsh(sortedmulti)` lockboxes (not in v1) |

### 4.7 Message signing

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| SG-01..02 | Sign message | A | `armory message sign <addr> [--format bitcoin-qt\|clearsign\|base64]` |
| SG-03/04 | Verify (bare / block) | A | `armory message verify [--address] <sig\|file>`; returns pass/fail plus the recovered address |
| SG-05 | Legacy sig-block helpers | A | Read-only support for old blocks (CRC-24 LSB-first quirk) |
| SG-06 | Daemon verification | M | → daemon (D-5) |
| — | BIP322 (segwit message signing) | D | Needed for messages from segwit addresses of new wallets |

### 4.8 Tools

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| TL-01 | Export transactions CSV | A | `armory history --csv <file>` |
| TL-02 | Export log | A | `armory debug export-log` (redacts paths/addresses on request) |
| TL-03 | ECDSA calculator | A | `armory tools ec {pubkey,add,mul,sign,verify}` |
| TL-04 | Broadcast raw tx | A | `armory tx broadcast --raw <hex>` |
| TL-05/06 | Message signing / address book | M | §4.7 / AR-10 |
| TL-07 | Submit bug report | C | Upload endpoint dead; print the GitHub issue URL |
| TL-08 | Verify signed package | C | ATI release signing keys/feeds are dead |
| TL-09 | `extras/` scripts | M | The useful ones are covered by CLI commands; the rest are dropped |
| TL-10 | Clipboard actions | B | `--copy` flag where a terminal clipboard is available (OSC 52) |
| TL-11 | Block-explorer links | B | Configurable URL template (default: none; mempool.space opt-in) |

### 4.9 Blockchain / node management

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| ND-01 | Auto-manage bitcoind | B | Detect only. `armory node status`; optional `armory node service-template {systemd,launchd}` prints a unit file. Never downloads or kills bitcoind. |
| ND-02 | bitcoin.conf management | C | Never write `bitcoin.conf`; cookie auth |
| ND-03/04/05 | SDM states, dashboard | B | `armory node status` (TUI: status bar + Node screen) |
| ND-06 | Online/offline switching | B | Automatic; `--offline` |
| ND-07 | Internet probe | C | Removed (privacy) |
| ND-08 | Torrent bootstrap | C | Tracker dead; Core removed bootstrap import |
| ND-09 | DB load/scan progress | B | Shows Core's `verificationprogress` and wallet rescan progress |
| ND-10 | Zero-conf tracking | B | Backend polling (`listsinceblock`) or ZMQ |
| ND-11 | Clear unconfirmed | B | `armory history --abandon <txid>` (Core `abandontransaction`) |
| ND-12/13 | Rescan / rebuild DB | B | `armory wallet rescan <id> [--from-height]`; `armory cache rebuild` |
| ND-14 | Factory reset | B | `armory config reset` (never touches wallets) |
| ND-15/16/17 | Flag files, load-failure recovery, old-DB cleanup | C | No Armory blockchain DB any more |
| ND-18/19 | Network indicator, disconnect notices | B | TUI status bar; CLI errors |
| ND-20 | Bitcoin network alerts | C | The alert system was removed from Bitcoin in 2016 |
| ND-21 | Surprise-tx detection | B | TUI notification on new wallet txs |
| ND-22 | Satoshi version awareness | B | Refuse Core < 21 (descriptors); warn below 29 |
| ND-23 | Install Core on Linux (dormant) | C | Use the distro/Homebrew packages |
| ND-24 | Non-standard ports/dirs | A | `--rpc-url`, `--rpc-cookie`, `--bitcoin-datadir` |
| ND-25 | Testnet | B/D | `--network {mainnet,testnet4,testnet3,signet,regtest}` |

### 4.10 Settings, command-line options, settings keys

| Group | V | Plan |
|---|---|---|
| ST-01..19 (settings dialog) | B | `armory config {list,get,set,reset}` editing `armory.toml`; TUI Settings screen |
| CL options | B | Kept with equivalents: `--datadir`, `--bitcoin-datadir`, `--rpc-url/--rpc-port`, `--network` (replaces `--testnet`), `--offline`, `--debug/-v`, `--logfile`, `--keypool`, `--rescan`, `--nospendzeroconfchange`, `--multisigfile`, `--force-wallet-check`. **Dropped**: `--satoshi-port`, `--bitcoind-path`, `--dbdir`, `--supernode`, `--rebuild`, `--redownload`, `--disable-torrent`, `--test-announce`, `--skip-announce-check`, `--skip-stats-report`, `--skip-online-check`, `--tor` (that flag only disabled the dead services), `--interport`, `--mtdebug`, `--netlog`, `--psn`, coverage flags, `--disable-modules`, `--disable-conf-permis`, `--enable/--disable-detsign` (always deterministic). |
| SK keys (75) | B | Port the read-and-used keys into `armory.toml`; drop window geometry, column widths, donation, announce, EULA and torrent keys. `armory config import-legacy <ArmorySettings.txt>` maps the rest. |
| SW per-wallet keys | A | `[wallet.<id>]` tables: `ledger-show`, `belongs-to`, `change-behavior`, `change-addr`, backup-reminder flag |

### 4.11 Help / updates / announcements

| ID | Feature | V | CLI / notes |
|---|---|---|---|
| HU-01 | About | A | `armory --version`, `armory about` (licence, credits) |
| HU-02/05/06/07/11/12 | Version check, secure downloader, announcements, changelog | C | All ATI services are dead; no phone-home. Updates come from the distro/Homebrew. |
| HU-03/04/13 | Troubleshooting/privacy/FAQ links | B | Local man pages + `docs/` |
| HU-08 | Notification popups | B | TUI notifications |
| HU-09 | EULA | B | AGPL notice on first run, no click-through |
| HU-10 | Intro dialog | B | First-run onboarding in the TUI |

### 4.12 Daemon (armoryd) — phase 3, see D-5

| IDs | V | Plan |
|---|---|---|
| RPC-05,06,07,11,12,13,14,15,16,17,18,19,20,25,26,27,28,29,30,31,33,34,35,41..46,48 | B | Same method names in `armory daemon` JSON-RPC (2.0), backed by the same library calls as the CLI; `help` returns the method list (fixes the doc mismatch) |
| RPC-01,03,04 | A | Signature-based received-from queries kept |
| RPC-02, RPC-47 | B | Accept PSBT or USTX |
| RPC-08 | A | `importprivkey` |
| RPC-09,10 | B | Proxy to Core (`getrawtransaction` needs `-txindex` or a wallet tx) |
| RPC-21..24 | B | Return PSBT by default, USTX on request |
| RPC-32 `sendtransaction` | B | **Fixed**: actually broadcasts (the legacy method only echoed `gettransaction`) |
| RPC-36 `watchwallet`, RPC-37 `sendlockbox` | C | SMTP email removed; replaced by a `--notify-cmd` hook that runs a local command on events |
| RPC-38..40 address metadata | A | Kept |
| AD-01..11 | B | Unix-socket or localhost + cookie auth (no rpcuser/password in a file), single-instance lock, periodic wallet check, `--notify-cmd` instead of email |

### 4.13 Plugins

| ID | V | Plan |
|---|---|---|
| PL-01/02 | C | Python plugin loading is removed. Extension happens through the daemon API and `--notify-cmd`. |
| PL-03 passphrase finder | B | `armory wallet find-passphrase <wallet> --template ...` (offline brute force over a user-defined pattern; a useful recovery tool) |
| PL-04 Dust-B-Gone | B | `armory utxo consolidate --dust-below <sats>` |
| PL-05/06 | C | Log viewer and search are built into the TUI |
| PL-07 Exchange rates | C | Third-party price feed (privacy); can be revisited |

### 4.14 Application shell / misc

| ID | V | Plan |
|---|---|---|
| MI-01..07 main window, menus, ledger, sorting, paging, row actions, status bar | B | TUI screens and key bindings (§5); `armory history` with `--sort`, `--limit`, `--offset` |
| MI-08 `bitcoin:` URI handler | B | Optional `.desktop` file (Fedora) and app bundle `CFBundleURLTypes` (macOS) that open `armory tui --uri` |
| MI-09 single instance | B | Lock file in the runtime dir per datadir |
| MI-10..12 tray, minimize | C | Not applicable to a terminal app |
| MI-13..15 shutdown, startup, heartbeat | B | Async runtime; graceful SIGINT/SIGTERM handling |
| MI-16 logging | B | `tracing` to `$XDG_STATE_HOME/armory/logs`; secrets never logged |
| MI-17 i18n | B | Phase 4: strings centralised so `po/` translations can be ported later |
| MI-18/19 theming, OS X specifics | B | Terminal colours; respect `NO_COLOR` |
| MI-20/21 progress/generic dialogs | B | `indicatif` progress in the CLI, TUI gauges |
| MI-22 wallet-for-address lookup | A | Library |
| MI-23 dormant UI | C | Not ported unless listed above |
| MI-24/25 formatting, encodings | A | Same display conventions (BTC 8 dp, Easy16, base58) |

## 5. TUI screens

One binary, `armory`; `armory tui` (or `armory` with no arguments in a terminal) starts the TUI. Screens:

As built (v0.1): Overview, Wallets, Receive, Send, History (transactions and coins), Offline, Lockboxes,
Backup, Tools, Settings, plus a command palette (`:`) that runs any `armory` command. The full command → key map is
in [`crates/README.md`](../../crates/README.md#terminal-interface). The original plan:

1. **Dashboard**: node status, sync progress, balances, recent activity, alerts.
2. **Wallets**: list → wallet detail (addresses, history, properties) → actions (receive, send, backup, passphrase).
3. **Send**: recipients, fee, coin control, change; review; sign / save unsigned.
4. **Receive**: new address, label, URI, Unicode QR.
5. **History**: combined ledger with filter, sort, paging, tx detail, comment, CSV export.
6. **Offline**: load PSBT/USTX, review, sign, merge, broadcast.
7. **Lockboxes**: list, detail, create, import/export, fund, spend, promissory notes.
8. **Backup/Restore**: paper, fragments, SecurePrint, test backup, restore flows.
9. **Tools**: message sign/verify, EC calculator, raw broadcast, address book.
10. **Settings**.

Every TUI action calls the same library function as its CLI command; the TUI adds no logic of its own. As built,
transactions go through shared prepare/execute operations and every other action runs the CLI command itself
in-process (output captured, prompts answered from TUI dialogs).

## 6. Upstream open issues

All 163 open issues on `etotheipi/BitcoinArmory` were triaged in [07](specs/07-upstream-open-issues.md). Counts:

- **By category:** 18 core, 38 backend, 18 GUI, 33 platform, 28 feature requests, 23 support, 5 spam.
- **By disposition:** 44 must-address, 72 obsoleted by this design, 19 to consider, 28 not applicable.

Seventy-eight issues were read in full; the rest were classified from the title only. The must-address items become
requirements and tests in the plan:

| Area | Requirement (issue refs) |
|---|---|
| Backups | Random Shamir coefficients plus set IDs (successor 0.96.3); fixed-size printable paper layout that fits A4 and Letter (#342); a backup test that prints PASS/FAIL plus the wallet ID (#157); a backup for metadata (comments, lockboxes), which paper restores lose (#264) |
| Wallet files | 0700/0600 permissions (#281); fsync before showing a new address (#9); UTF-8 labels and paths, plus defined passphrase bytes matching Python 2 behaviour (#20, #39, #336); compressed-key import and sweep (#190, #168, #16) |
| Offline signing | The signer derives any chain index the unsigned tx references (#111) |
| Transactions | Typed insufficient-funds errors and a send-max mode (#46); `testmempoolaccept` with the verbatim reject reason (#34, #22); rebroadcast of dropped own txs (#12); defined self-send ledger semantics and richer CSV (#191, #192, #247); P2SH and bech32 parsing (#127) |
| Lockboxes | Verify each signature when it is added (#291); strict parser and complete-signature check (#313); duplicate detection instead of overwrite (#252) |
| Backend | Remote Core over RPC (#63); regtest/signet/testnet4 (#348); reorg handling (#14); sync cursor and birthday rescan (#72, #345); connection state machine (#30, #164, #194); config precedence CLI > env > file > default (#288) |
| Build | Portable baseline binaries, no `target-cpu=native` (#335); self-contained offline install and docs (#270, #215); log rotation (#251) |

**The successor project.** Development moved to `goatpig/BitcoinArmory` in 2017 (#341). That project later shipped
SegWit, bech32, RBF/CPFP, `estimatesmartfee`, cookie auth and, in 0.97, an `.lmdb` wallet format with BIP32. Those
features confirm the bucket-D list above. Importing goatpig-era `.lmdb` wallets (#355, #356) is a **roadmap item,
not v1**: the format encrypts public data too and needs its own spec. The successor relicensed to MIT from 0.94. This
tree is AGPL-3.0 (ATI, 2011–2015), so the Rust rebuild, as a derivative work, stays AGPL-3.0.

## 7. Delivery status (v0.1)

Delivered rows are covered by CLI integration tests (`crates/armory/tests/cli.rs`), the end-to-end test against
`bitcoind -regtest` 31.1 (`tests/regtest.rs`, run in CI) and the TUI tests (every screen rendered, every advertised
key exercised, a payment through the dialogs against regtest Core). Every delivered command is reachable from the TUI.

| Area | Delivered | Deferred (reason) |
|---|---|---|
| Wallets | WM-01, 03, 04, 05, 06, 07, 08 (per-action passphrase), 09 (the TUI never keeps keys unlocked, so there is nothing to time out), 10 (`wallet remove`, renames), 14/15 (`legacy wallet import`, `wallet import`), 16 (`--replace`), 18 (`wallet check`), 21 (`wallet sync`), 22, 24, 25, 26/27, 28; KDF cost in `wallet show` (13) | WM-02 ledger visibility and WM-23 ledger filter (one wallet per screen in the TUI makes them moot for now); WM-11 owner field (no consumer yet); WM-12 is `wallet sync --gap`; WM-13 benchmark; WM-17 damaged-wallet recovery modes (needs corrupted-file fixtures first) |
| Receiving | AR-01, 03, 04 (terminal QR), 05 (`legacy address show`; modern `address list`), 06 (`wallet export-keys`, `legacy address keys`), 07 (legacy wallets; modern wallets sweep instead), 08, 09, 10, 11, 14 | AR-02 no-backup warning; AR-04 `--png` |
| Sending | SD-01/02, 03, 04 (`--from-utxo`, TUI coin marking), 06, 07, 08, 09, 12 (`lockbox:ID`), 13, RBF bump, abandon | SD-05 change options (a new change address every time is the modern default) |
| Offline | OS-01, 03, 04, 05 (files), 06 (everything but sync/broadcast works without a node) | — |
| Backups | BK-01/02 (TUI Backup screen), 03 (text), 04, 05 (`backup file`), 06, 07, 08, 09, 11 (`restore … --test`) | BK-03 PDF/HTML layouts; BK-10 watch-only from root data (import the watching-only file instead) |
| Lockboxes | MS-01..11 (every cosigner signature is verified before finalizing), 15, 16; SegWit `wsh(sortedmulti)` lockboxes | MS-12..14 simulfunding / promissory notes (rarely used; the fixtures stay for a later port); MS-17 per-lockbox ledger (balance and coins are shown) |
| Messages | SG-01..05, BIP322 | — |
| Tools | TL-01, 04 (`tx broadcast --raw`), 10 (OSC 52 copy in the TUI) | TL-02 log export and MI-16 logging (no log yet); TL-03 EC calculator; TL-11 explorer links |
| Node | ND-03/04/05, 06, 09 (verification progress), 10 (30 s polling), 11, 12 (`--rescan-from`), 14 (`config unset`), 18/19, 21 (status-line notice), 22 (warns below 29), 24, 25 | ND-01 service templates |
| Settings | `config list/set/unset/path`; TUI Settings (network, node connection, save as defaults) | `config get/reset`, `import-legacy`, per-wallet keys |
| Shell | HU-01, 03/04/13 (man page, docs), 09 (licence in `about`), 10 (empty-state guidance), MI-01..07, 13–15, 20/21, 22, 24/25; Fedora RPM, Homebrew formula, portable archive | MI-08 URI handler, MI-09 single-instance lock, MI-17 i18n, MI-18 `NO_COLOR` |
| Later phases | — | Daemon (§4.12, D-5), plugins PL-03/04, goatpig 0.97 `.lmdb` import, Electrum backend |

