# Security review of the money paths (read-only, 2026-10-01)

Reviewed at `f045c104` by an AI reviewer with no human involvement; it is input to a human review, not a
replacement for one. Scope: `sign.rs`, `modern.rs`, `store.rs`, `io.rs` capture mode, `rpc.rs`. Line numbers
refer to `f045c104`.

**Status.** Defects D1–D4 were fixed the same day (`0dcf84b5` sign.rs: sighash, prevout trust, vsize;
`52c7a8b6` ops/core/rpc: bump-fee txid, fee ceilings, response size). Concerns C1–C8 are open.
Library claims were checked against the vendored sources (bitcoin 0.32.102, secp256k1 0.29.1, argon2 0.5.3,
bip39 2.2.2).

## CLAUDE.md rules, as actually kept

- Rule 2 (all I/O through `io.rs`, prompts matched by prefix): kept. The prefix matching has a
  footgun but no secret leak was found (C7).
- Rule 3 ("never trust Core's PSBT blindly"): not kept. `check_psbt` does guard outputs and the
  stated fee cap, but four things it does not look at let a malicious or buggy node move money
  (D1–D4). The multisig cosigner verification is real but accepts any sighash type (C1).
- Rule 4 (atomic writes, 0600/0700, world-readable refused, AAD-authenticated public data): mostly
  kept. The `.bak` / `_backup.wallet` twins are never permission-checked, the 0600 mode is applied
  only when the temp file is created, and the AAD binds far less than "public data" (C4, C6).
- Rules 1, 5, 6: out of scope.

---

## Defects

### D1 — The node (or the online machine, for offline signing) chooses the sighash type; the wallet signs with it

**Class**: defect
**Where**: `crates/armory-wallet/src/sign.rs:288-326` (`check_psbt` never reads
`psbt.inputs[i].sighash_type`), `sign.rs:133` (`psbt.sign` honours it), `sign.rs:167-169`
(cosigner signatures are verified against whatever type *they* declare), `sign.rs:329-415` and
`crates/armory/src/cli_tx.rs:173-203` (the summary shown before confirming does not display it).
**What**: rust-bitcoin 0.32 derives the sighash from the PSBT input field and defaults to
`SIGHASH_ALL` / `Default` only when the field is absent (`psbt/map/input.rs:227-243`
`Input::ecdsa_hash_ty` / `taproot_hash_ty`; `psbt/mod.rs:564-610` `sighash_taproot`). `walletcreatefundedpsbt` never sets
this field, so its presence is itself a sign of a hostile node; nothing in `check_psbt`, `sign_psbt`,
`finalize` or `summarize` notices it. A node that sets `sighash_type = NONE` (or
`SINGLE|ANYONECANPAY`) on each input gets back, via `ops::execute_unlocked` →
`core.broadcast`, a fully signed transaction whose signatures do not commit to the outputs. The node
operator can rewrite every output to their own script and relay that instead. Every input's full
value is at risk, on every script type (P2WPKH, P2TR, P2PKH, lockbox multisig). The same applies to
`tx sign` (`cli_tx.rs:286-296`), where the PSBT comes from the online machine and there is no
`check_psbt` at all; the printed summary cannot reveal the problem.
**Repro**: extend `sign_and_finalize_all_script_types` (`sign.rs:432-548`): after building `psbt`,
set `psbt.inputs[0].sighash_type = Some(EcdsaSighashType::None.into())` and
`psbt.inputs[1].sighash_type = Some(TapSighashType::None.into())`. Expected: `check_psbt` returns
`Err`. Today: `Ok`, `sign_psbt` returns 3, `finalize` succeeds, and
`ecdsa::Signature::from_slice(&tx.input[0].witness.to_vec()[0]).sighash_type == None`.
**Fix**: in `check_psbt`, refuse any input whose `sighash_type` is set to anything but
`All`/`Default`; in `sign_psbt`, set `inp.sighash_type = None` for every input before
`psbt.sign` (so the wallet never signs with a type it did not choose); in `finalize`, refuse
cosigner signatures whose `sighash_type != All`; print the type in `summary_text` when it is not
ALL. Four small edits, no new abstractions.

### D2 — Prevout amounts of legacy inputs are taken on faith; the fee cap is computed on the lie

**Class**: defect
**Where**: `crates/armory-wallet/src/sign.rs:50-57` (`prevout`), used by `check_psbt` at
`sign.rs:292-298` and by `summarize` at `sign.rs:331-336`.
**What**: `prevout` returns `witness_utxo` for any script type and otherwise indexes into
`non_witness_utxo` without checking that `non_witness_utxo.compute_txid() ==
previous_output.txid`. rust-bitcoin does the same when signing (`psbt/mod.rs:621-632`
`spend_utxo`), and for `Bare`/`Sh` outputs it uses `legacy_signature_hash`
(`psbt/mod.rs:503-558` `sighash_ecdsa`), which does not commit to the amount. So for a legacy-1.35 P2PKH input or
a P2SH lockbox input, a node can claim the coin is worth 0.1 BTC when it is worth 5 BTC: the
"fee" `check_psbt` computes is small, the signature the wallet produces is nonetheless valid on
chain, and the 4.9 BTC difference goes to whoever mines the block. Nothing downstream catches it:
rust-bitcoin's `extract_tx` fee-rate limit (`psbt/mod.rs:190-206`, `fee()` at `717-727`) sums the
same PSBT-claimed amounts. SegWit v0 and Taproot inputs are not affected (their sighash commits to
the amount, so a lie just invalidates the signature). Note that `prepare_send` spends from the
whole Core watch-only wallet, so legacy coins can be pulled into an ordinary `send` even when the
chosen account is BIP84/BIP86 (`ops.rs:172-177` only restricts the *change* account).
Sub-point: `input_total += out.value.to_sat()` at `sign.rs:298` and `t + o.value.to_sat()` at
`sign.rs:333` are unchecked; `Amount` consensus-decodes any `u64` (`bitcoin/src/lib.rs:197-202`)
and no `[profile]` sets `overflow-checks`, so in release builds two inputs claiming `2^63` each wrap
to 0. With the txid check in place this is only a DoS/panic in debug; today it is another knob on
the same lie.
**Repro**: in `sign_and_finalize_all_script_types`, replace input 2's `non_witness_utxo` with a
copy of `funding` whose output 2 is `10_000` sat (its txid no longer matches `fid`), or set
`psbt.inputs[2].witness_utxo = Some(TxOut { value: 10_000, script_pubkey: aleg.script_pubkey() })`,
and lower the single output so the claimed fee is 10_000. Expected: `check_psbt` returns `Err`.
Today: `Ok`; after `sign_psbt` + `finalize`, the legacy signature verifies against the real
`prevouts[2]` (the existing verification block at `sign.rs:536-547`) while the real fee is
`100_000 - output`.
**Fix**: in `prevout`, for the `non_witness_utxo` branch require `t.compute_txid() == op.txid`
(else `None`), and return `None` when `witness_utxo` is present but `script_pubkey` is not
`is_witness_program()`. Use `checked_add` at lines 298 and 333.

### D3 — `bump-fee` lets the node define which payments are "requested"

**Class**: defect
**Where**: `crates/armory/src/ops.rs:324-351` (`prepare_bump`),
`crates/armory-node/src/core.rs:475-478` (`wallet_tx_hex`).
**What**: the outputs that `check_psbt` must find in the replacement are taken from the hex that
`gettransaction` returns, and that hex is never checked to hash to the `txid` the user named. A
node can return a forged "original" containing an output to an attacker script, then return a
`psbtbumpfee` PSBT paying that script from the wallet's coins. `check` passes because the attacker
output is now an expected payment. With `--yes` (`cli_tx.rs:226` → `io::confirm`) nothing stops
the broadcast; without it the user sees the output in the summary with no "(change / own)" marker
and has to notice.
**Repro**: mock-Core test (a mock exists per CLAUDE.md; not reviewed): `gettransaction` returns a
tx with one foreign output `X` whose txid differs from the requested one; `psbtbumpfee` returns a
PSBT spending a wallet P2WPKH coin to `X` plus change. Run `tx bump-fee --yes`. Expected: error
"transaction does not match txid". Today: broadcast.
**Fix**: after `deserialize_hex`, `ensure!(original.compute_txid().to_string() == txid)`.

### D4 — The fee cap is derived from the node's own fee estimate, with no ceiling

**Class**: defect
**Where**: `crates/armory/src/ops.rs:57-63` (`fee_rate` falls back to `core.estimate_fee`),
`ops.rs:87` (`max_fee = rate × vsize × 2 + 1000`), `crates/armory-node/src/core.rs:425-431`
(only a *floor* is applied to `estimatesmartfee`), `crates/armory-wallet/src/sign.rs:383-403`
(`vsize_estimate` honours a PSBT-supplied `witness_script`/`redeem_script` on any input, so the
node can also inflate the size term roughly nine-fold per input with a 15-of-15 script).
**What**: without `--fee-rate`, the only number the cap is built from comes from the node being
guarded against. A node answering `estimatesmartfee` with 1 BTC/kvB makes `max_fee` ≈ 30 M sat for
a 150 vB transaction, and its PSBT can then carry that fee. For SegWit inputs the loss is bounded by
rust-bitcoin's `extract_tx` limit of 25 000 sat/vB (`psbt/mod.rs:136`) because those amounts must
be true; for legacy inputs D2 removes even that bound. With `--yes` this is non-interactive; the
summary does show the fee, so an attentive interactive user would refuse.
**Repro**: mock-Core test: `estimatesmartfee` → `{"feerate": 1.0}`, `walletcreatefundedpsbt` →
PSBT with the requested payment, change to the wallet, and 3 000 000 sat fee on a 150 vB tx. Run
`send --yes` without `--fee-rate`. Expected: refused. Today: `check_psbt` passes
(`max_fee ≈ 30 M`), signed and broadcast.
**Fix**: cap the estimate (refuse or clamp anything above, say, 1 000 sat/vB unless the user passed
`--fee-rate`), add an absolute `max_fee` ceiling (configurable, default on the order of Core's
`-maxtxfee` 0.1 BTC), and compute `vsize_estimate` from the prevout script type only, ignoring
PSBT-supplied scripts on non-P2WSH/P2SH prevouts.

---

## Concerns

### C1 — `finalize`: cosigner signature checks are weaker than they look

**Where**: `sign.rs:154-175`, `191-216`; `crates/armory-wallet/src/lockbox.rs:163-185`.
**What**: (a) each cosigner signature is verified against the sighash type it declares itself
(`sig.sighash_type`), not against ALL — a cosigner's NONE signature passes and is broadcast
(see D1). (b) The `witness_script` (P2WSH) and `redeem_script` (P2SH) are taken from the PSBT
and never checked to hash to the prevout's script; a wrong script only yields an invalid
transaction, so no loss, but the "verified" signatures were verified against the wrong script.
(c) `script_keys` accepts any `OP_m <pushes...> X Y` without checking that `X == OP_n`,
`Y == OP_CHECKMULTISIG`, `1 ≤ m ≤ n ≤ 16`, or key lengths of 33/65. (d) rust-bitcoin's
`verify_ecdsa` rejects high-S signatures (`secp256k1/src/ecdsa/mod.rs:194`), so that part is sound.
**Evidence to settle**: a test with a `witness_script` whose sha256 differs from the prevout, and
one with a cosigner `partial_sig` of type NONE, both expecting `finalize` to fail.
**Fix**: compare `script.wscript_hash()` / `script.script_hash()` with the prevout; require
`sig.sighash_type == All`; tighten `script_keys`.

### C2 — Offline `tx sign` has no check and no confirmation step

**Where**: `cli_tx.rs:286-296`, `ops.rs:377-384`.
**What**: the summary is printed and signing proceeds straight to the passphrase prompt; with
`--passphrase-file` (`context.rs:82-86`) the whole thing is non-interactive. There is no
request to check against (by design), but there is also no `confirm`, and the summary omits
sighash types (D1) and shows a fee computed from PSBT-claimed amounts (D2). A compromised online
machine therefore has a one-step path to a signature.
**Evidence to settle**: product decision; at minimum a test that `tx sign` refuses when stdin is
not a terminal and `--yes` is absent, as `complete` already does.
**Fix**: give `TxCmd::Sign` a `--yes` flag and route it through `confirm` after the summary, as
`complete` does at `cli_tx.rs:225-226`.

### C3 — `check_psbt` relies on `finalize` to catch inputs that were not signed

**Where**: `ops.rs:362` ignores the count returned by `sign_psbt`; `sign.rs:249` and `235` make
`finalize` fail on an unsigned single-sig input.
**What**: correct today, but the guarantee lives in a different function from the one that claims
it. Imported compressed keys are built as uncompressed (`sign.rs:100`), so a compressed-key P2PKH
coin would silently never be matched by `annotate_legacy_inputs` and would surface only as
"input N: not signed". To answer the brief directly: P2PKH, P2WPKH, P2TR key-path, P2WSH and
bare-P2SH multisig are handled; P2SH-wrapped SegWit (P2SH-P2WPKH, P2SH-P2WSH) is unsupported and
fails loudly at `sign.rs:260` ("unsupported script type"); the only *silent* skip is an input for
which the wallet finds no key (rust-bitcoin's `continue` in `bip32_sign_ecdsa`), and that is the
count `ops.rs:362` discards.
**Evidence to settle**: a test importing a compressed WIF into a legacy account and spending it.
**Fix**: `ensure!(signed == psbt.inputs.len())` in `execute_unlocked`.

### C4 — v2 wallet: what the AAD and `verify_public` do and do not cover

**Where**: `crates/armory-wallet/src/modern.rs:296-298` (AAD = `format|version|network|id`),
`438-442`, `467-473`, `478-483`, `489-539`.
**What**:
- Bound by the AEAD: the ciphertext, nonce (implicitly) and the four AAD fields. Swapping the
  encrypted blob between two files fails on `id` (tested at `modern.rs:970-973`); replacing `id`
  too then fails `verify_public` on the xpubs.
- Re-verified from the secrets on unlock: account `path` prefix, `xpub`, legacy `root_pubkey`,
  `chaincode`, `imported_hash160` ↔ `imported_keys`. Good.
- Not bound, not verified: `next_receive`/`next_change` (edit → address reuse or a watch range
  that no longer covers old coins; `own_scripts` at `ops.rs:37` then rejects them as inputs — a
  denial, not a loss), `address_labels`, `tx_comments`, `label`, `description`, `birthday`
  (set high → rescan misses history), `created`, and the `kdf` block (a tampered KDF only yields
  `WrongPassphrase`, so this is not a downgrade path).
- Watching-only and `--no-encrypt` files have **no** integrity at all: a tampered xpub in a
  watching-only file hands out attacker addresses as receive addresses and nothing can notice.
- `id` is not validated as 8 hex chars on load (`modern.rs:853-863`) and is interpolated into the
  RPC request path at `crates/armory-node/src/rpc.rs:77` → `/wallet/armory-<id>`; a file with
  CR/LF in `id` would inject headers into the request to Core.
- KDF floors: `Params::new` enforces argon2's minimum of 8 KiB / 1 pass
  (`argon2/src/params.rs:46-55`); the CLI floors at 1 MiB (`cli_modern.rs:116`); `update_secrets`
  re-seals with the file's own cost (`modern.rs:547-563`), so a weak choice at creation persists
  through `migrate_legacy`. `kdf_memory_mib.max(1) * 1024` overflows `u32` above 4 194 303 MiB and
  wraps to a small value (release) or panics (debug).
- Nonce: 24 random bytes from `OsRng` per `seal` (`modern.rs:435-436`); unique per write.
**Evidence to settle**: a test that edits `next_change` / `birthday` / `kdf.memory_kib` in the JSON
and expects `Tampered` on unlock; a test that a watching-only file with a swapped xpub is detected
(it cannot be, today).
**Fix**: include a hash of the canonical public section in the AAD (or sign it), validate `id`,
refuse `memory_kib < 64 MiB` on unlock unless a `--weak-kdf` style flag is present.

### C5 — Zeroization gaps

**Where / what** (all copies of key material that outlive `Zeroizing`):
- `modern.rs:257`, `sign.rs:17-19`: `Unlocked.master` and `WalletKeys` (an `Xpriv` and a
  `BTreeMap<_, PrivateKey>`) are never erased; `secp256k1::SecretKey` is `Copy` and
  `impl_non_secure_erase` (`secp256k1/src/key.rs:60`) is opt-in, so every derived child key stays
  in freed heap/stack memory.
- `modern.rs:321-322`: `let mut mix = entropy.to_vec(); mix.extend_from_slice(extra)` reallocates,
  leaving an unzeroized copy of the fresh entropy; `h` (the new entropy) at `323` is a plain array.
- `modern.rs:272-273, 516, 528-529, 741`, `sign.rs:96`: `hex::decode` of keys into plain `Vec`s /
  arrays before wrapping.
- `crates/armory/src/io.rs:101-111`: `read_all` returns a plain `String`, and `v?.to_string()` at
  `103` copies the captured value out of `Zeroizing` — "backup lines" and "fragments" are the legacy
  root key. `io.rs:95-97`: the stdin `line` buffer is dropped unzeroized. `context.rs:84`: the
  passphrase file contents `s` likewise.
- `crates/armory/src/tui/app.rs:258`: on command failure the captured output (which may contain a
  mnemonic printed by `wallet new`/`restore`) is copied into a plain `String` for the error.
- `modern.rs:460`: the `Plaintext` `serde_json::Value` is cloned (unencrypted wallets only).
**Evidence to settle**: a heap-dump test after `drop(unlocked)` searching for the master chain code
or a child key.
**Fix**: wrap `Unlocked`/`WalletKeys` in a `Drop` that calls `non_secure_erase` on the keys;
`Vec::with_capacity` at 321; make `read_all` return `Zeroizing<String>`.

### C6 — `store.rs` / wallet files

**Where**: `crates/armory-wallet/src/store.rs:65-84, 90-103, 151-157`, `modern.rs:869-893`.
**What**:
- `atomic_write` does fsync the temp file (`80`), rename (`82`), fsync the directory (`83`). Good.
- `opts.mode(0o600)` applies only when the temp file is *created*; `truncate(true)` on a
  pre-existing `<name>.tmp` keeps its mode. A leftover temp file from a crash is 0600 anyway, so
  this needs an attacker who can already write to the wallet directory. Use `create_new(true)` (and
  unlink a stale `.tmp` first) or `set_permissions` after open.
- The world-readable check runs only on the main file: `modern.rs:879` and `store.rs:153`. The
  `.bak` and `_backup.wallet` twins hold the same secrets and are never checked, including when
  `.bak` is the file actually loaded (`modern.rs:885`). The check-then-open gap itself is not a
  real TOCTOU: the check is about who *else* can read the file, and anyone who can flip its mode
  between the two calls already has that access.
- Crash between the two writes in `save` (`872-873`): main = new, `.bak` = old; `load` prefers
  main whenever it parses, so the new version wins. But the fallback at `882-891` triggers on
  *any* error including `UnsupportedVersion`: an older binary opening a newer file whose `.bak` is
  still the previous version will silently restore the old `.bak` over the newer main. Fall back
  only on I/O/JSON errors.
- Legacy `save` (`186-196`): flag → main → backup → unflag; a crash leaves the backup flag, and
  `consistency_check` copies main over backup. Converges on main. Fine.
- `context.rs:113-117`: 0700 is set only when the directory is created; an existing 0755 wallet
  directory is accepted silently.
**Evidence to settle**: tests for the `.bak` permission case and the `UnsupportedVersion` fallback.
**Fix**: `create_new(true)` for the temp file (unlinking a stale one first); run
`check_permissions` on both twins in `ModernWallet::load` and `WalletFile::open`; fall back to
`.bak` only on I/O or JSON errors, never on `UnsupportedVersion`.

### C7 — `io.rs` capture mode: prefix matching

**Where**: `io.rs:75-84`; keys built at `tui/app.rs:280`, `tui/screens.rs:516-562, 597-612,
1634, 2016-2036, 2236-2247`.
**What**, answering the brief's question literally: a "BIP39 passphrase" answer cannot be fed to a
"Passphrase for wallet …" prompt — matching is `prompt.starts_with(key)`, positional and
case-sensitive, and no key is a prefix of another prompt family except the bare `"Passphrase"`
key from the command palette (`screens.rs:2238`), which deliberately answers both "Passphrase for
wallet …" and "Passphrase of legacy wallet …". Two real hazards remain: (1) the palette registers
the one free-text "Input" under seven keys at once (`screens.rs:2243-2247`: "Recovery phrase",
"Private key", "backup lines", "fragments", "signed block", "SecurePrint code",
"BIP39 passphrase"), so `wallet restore --bip39-passphrase` run from the palette gets the recovery
phrase as its 25th word and silently restores a different wallet; (2) `wallet_command` pushes the
*selected* wallet's passphrase under "Passphrase for wallet" without the ID, so any command that
unlocks a second wallet gets the wrong passphrase (an error, not a leak). No path was found where
a prompt answer is echoed: bip39 errors print a word index, not the word
(`bip39/src/lib.rs:145`); `hex_decode`/`WrongPassphrase`/`Mnemonic` errors carry no input; the
capture buffer is `Zeroizing` (`io.rs:16`); there is no log file (logging is listed as deferred in
CLAUDE.md). The one copy is `app.rs:258` (C5).
**Evidence to settle**: a test that runs `wallet restore --bip39-passphrase` through
`run_captured` with palette-style inputs and asserts the resulting fingerprint; grep of every
`bail!`/`anyhow!` that interpolates a value read from `secret`/`read_all`.
**Fix**: key the palette "Input" to one prompt (ask which), include the wallet ID in the passphrase
key.

### C8 — `rpc.rs` hand-written HTTP

**Where**: `crates/armory-node/src/rpc.rs:63-72, 75-122, 125-172`.
**What**:
- No size limits: `Content-Length` (`145`, `166`) and chunk sizes (`156`, `161`) are allocated as
  declared; the header loop (`136-150`) and the `read_to_end` fallback (`169`) are unbounded. A
  hostile node can exhaust memory. `n + 2` at `161` with `n = usize::MAX` wraps in release and then
  `chunk[..n]` panics (the TUI catches job panics; the CLI aborts).
- Cookie: read on every call (`65-68`), trimmed, base64'd — correct for Core restarts; no
  permission check on the cookie (acceptable: Core creates it 0600). The credential strings
  (`raw`, `credentials`, the whole `req`) are plain `String`s; `Auth` and `NodeConfig`
  (`core.rs:81-88`) derive `Debug` including the password — no `{:?}` use was found, but the
  derive invites one.
- Plain HTTP to `127.0.0.1` by default (`core.rs:94-95`); documented.
- Which results are trusted where `check_psbt` should guard: `estimatesmartfee` (D4),
  `gettransaction` (D3), the PSBT's prevout data (D1, D2). `listunspent` amounts (`core.rs:408-423`,
  `sats()` at `196-198`) only shape the *request* for `--max`/sweeps and are then bounded by the
  fee cap; `testmempoolaccept`/`sendrawtransaction` carry a transaction already finalized locally.
**Evidence to settle**: a malicious-server test sending `Content-Length: 18446744073709551615`
and a chunk header `ffffffffffffffff`.
**Fix**: cap bodies at a few MiB, `checked_add` at 161, cap header count, drop `Debug` from `Auth`.

---

## What is done right (do not re-check)

- Ownership is decided locally. `own_scripts`/`account_scripts` (`ops.rs:24-55`) derive every
  script from the wallet's own xpubs and legacy chain; Core's `ismine`/addresses are never consulted
  for the check. The change address is minted locally before Core is called (`ops.rs:243`).
- `check_psbt` output logic (`sign.rs:300-324`): payments matched by exact `(script, amount)`,
  duplicates handled by removal, every other output must be own, one sweep output, fee via
  `checked_sub`, missing payments refused. The existing test covers altered payment, low cap and
  foreign output.
- No sat/BTC confusion found on the request path: amounts parse as exact decimal
  (`ops.rs:151` `Amount::from_str_in`), go to Core as exact strings (`core.rs:format_btc`), fee
  rates convert BTC/kvB → sat/vB once (`core.rs:428-429`) and are passed as sat/vB (`fee_rate`
  option, `core.rs:445`, `469`); `sats()` rounds floats only for display/`--max` totals that the
  cap then bounds.
- Signing: own signatures come from libsecp256k1 (low-S by construction); cosigner signatures go
  through `verify_ecdsa`, which rejects high-S. Multisig signatures are collected in script key
  order and truncated to `m` (`sign.rs:201-216`). rust-bitcoin returns an error only for inputs
  the wallet has a key for, so foreign inputs are skipped, not failed.
- Taproot: fake prevout amounts invalidate the signature (`Prevouts::All`); P2TR key-path
  finalization is correct.
- v2 crypto: Argon2id v0x13 → 32-byte key, XChaCha20-Poly1305, fresh 24-byte `OsRng` nonce per
  seal, `id` in the AAD (swap test exists), master fingerprint re-checked and every
  xpub/legacy root/imported key re-derived on unlock (`modern.rs:478-539`). `Secrets` zeroizes its
  strings on drop; `SecretBox`'s `Debug` is redacted; passphrases and the capture buffer are
  `Zeroizing`. BIP39 material specifically: `bip39::Mnemonic` is built with the `zeroize` feature
  and derives `Zeroize, ZeroizeOnDrop` (`bip39/src/lib.rs:178`), the 64-byte seed is wrapped at
  `modern.rs:292`, raw entropy at `318`, `344`, `476`, and the mnemonic string handed to the user
  at `282`.
- Files: temp file 0600 → `write_all` → `sync_all` → `rename` → directory `sync_all`; wallet dirs
  created 0700; world-readable main files refused fail-closed; `load` prefers the main file.
- `io::confirm` refuses to proceed non-interactively without `--yes` (`io.rs:119-121`), so the
  CLI cannot be driven past the summary by a closed stdin.
- `unsafe_code = "forbid"` workspace-wide.

---

Summary: 4 defects (D1 sighash type honoured from PSBT; D2 legacy prevout amounts unverified; D3
bump-fee original tx unverified; D4 fee cap derived from node estimate), 8 concerns.
