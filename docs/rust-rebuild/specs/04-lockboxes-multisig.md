# 04 — Lockboxes (multisig), promissory notes, simulfunding, signature collection

Status: derived from source at HEAD (`2a6fc53`), Python 2 not executed. Every
layout and ID formula below was re-implemented in Python 3 and checked against
the golden fixtures and every test vector in `pytest/testMultisig.py`; all IDs
recompute exactly (see §6, §7).

Source files: `armoryengine/MultiSigUtils.py` (MSU), `armoryengine/Transaction.py`
(TX), `armoryengine/ArmoryUtils.py` (AU), `armoryengine/AsciiSerialize.py`,
`armoryengine/BinaryPacker.py`, `cppForSwig/BtcUtils.h`, `ui/MultiSigDialogs.py`
(MSD), `ui/MultiSigModels.py`, `ui/TxFrames.py`, `ArmoryQt.py`, `qtdialogs.py`,
`armoryd.py`.

---

## 0. Primitives shared by every object in this spec

| Name | Encoding | Source |
|---|---|---|
| `UINT8/32/64` | little-endian fixed width | BinaryPacker.py:45-60 |
| `VAR_INT` | Bitcoin CompactSize: `<0xfd` 1 byte; `0xfd`+u16; `0xfe`+u32; `0xff`+u64 | AU:2284-2289 |
| `VAR_STR` | `VAR_INT(len) ‖ bytes` | BinaryPacker.py:71 |
| `MAGIC` | 4 network magic bytes. mainnet `f9 be b4 d9`, testnet `0b 11 09 07` | AU:474, AU:491 |
| `hash160(x)` | `RIPEMD160(SHA256(x))` (via C++ SWIG) | AU:1818-1820 |
| `hash256(x)` | `SHA256(SHA256(x))` | AU:1815-1817 |
| `base58(b)` | Bitcoin alphabet; **no checksum**; each leading `0x00` byte → `'1'` | AU:1997-2021 |
| `addrStr(h160)` | Base58Check(`ADDRBYTE ‖ h160`): mainnet `0x00`, testnet `0x6f` | AU:2088-2100, AU:480/497 |
| `p2shAddrStr(h160)` | Base58Check(`P2SHBYTE ‖ h160`): mainnet `0x05`, testnet `0xc4` | AU:481/498 |
| `MULTISIG_VERSION` | `1` | MSU:12 |
| `UNSIGNED_TX_VERSION` | `1` | TX:19 |
| `LB_MAXM`, `LB_MAXN` | `7`, `7` (UI combo max and armoryd check) | AU:174-175, armoryd.py:2147-2156 |

`toBytes`/`toUnicode` convert between Python `unicode` and UTF-8 bytes. All
string fields (names, descriptions, comments, labels) are UTF-8 on the wire.

### 0.1 ASCII armor ("AsciiSerializable")

Every exchangeable object (`DecoratedPublicKey`, `MultiSigLockbox`,
`MultiSigPromissoryNote`, `UnsignedTransaction`) has the same armored form
(AsciiSerialize.py:65-78, AU:1326-1351):

```
=====<BLKSTRING>-<asciiID>===========...   (header padded with '=' to width W)
<base64 of serialize(), wrapped at W chars per line>
...
================...                        (exactly W '=')
```

* Writer (`makeAsciiBlock`, AU:1326-1335): `W = 64` at HEAD; `newline='\n'`;
  standard base64 with padding. The header line is `'=====' + BLKSTRING + '-' + asciiID`
  left-justified to W with `'='` (it is longer than W if the ID is long — no truncation).
* **All golden fixtures and all test vectors use W = 80** and the fixture files
  use CRLF line endings (§6). The shallow git history (root commit `72447c5`,
  2015-02-26) already has `wid=64`, so the switch from 80 predates the clone.
  Rust writer: choose 64 to be byte-identical with HEAD output; reader MUST be
  width- and line-ending-agnostic.
* Reader (`readAsciiBlock`, AU:1338-1351): `tokens = text.strip().split()`
  (any whitespace); require `tokens[0].startswith('=====')` and
  `tokens[-1].startswith('======')`; `head = tokens[0].strip('=')`;
  `raw = b64decode(''.join(tokens[1:-1]))`. Because it splits on whitespace,
  the header must not contain spaces, and trailing spaces after the footer
  (testMultisig.py:608 has one) are harmless.
* **Bug: the type check is dead.** `readAsciiBlock` overwrites its `headStr`
  argument with `''` (AU:1339), so `unserializeAscii` accepts any
  `=====...` block regardless of BLKSTRING and then tries to parse the bytes
  as the requested class. Rust SHOULD verify `head.split('-')[0] == BLKSTRING`.
* `expectID = head.split('-')[-1]` is passed to `unserialize` and compared to
  the recomputed ID (AsciiSerialize.py:77). Mismatch handling differs by class:
  Lockbox raises `UnserializeError` (MSU:416-420), USTX raises (TX:2237-2240),
  DecoratedPublicKey and PromissoryNote silently `return None` (MSU:725-727,
  MSU:984-986).

| Class | BLKSTRING | asciiID | OBJNAME |
|---|---|---|---|
| DecoratedPublicKey | `PUBLICKEY` | pubKeyID (12 chars) | `PublicKey` (MSU:618-619) |
| MultiSigLockbox | `LOCKBOX` | lockbox ID (8 chars) | `Lockbox` (MSU:242-243) |
| MultiSigPromissoryNote | `PROMISSORY` | promID (8 chars) | `PromNote` (MSU:817-818) |
| UnsignedTransaction | `TXSIGCOLLECT` | USTX ID (8 chars) | `UnsignedTx` (TX:1933-1934) |

### 0.2 The four ID formulas (they are all different — do not unify)

| Object | Formula | Network-dependent? | Source |
|---|---|---|---|
| Lockbox | `base58(hash160(MAGIC ‖ msScrAddr))[1:9]` — **skips char 0**, takes 8 | yes (MAGIC in preimage) | MSU:80-100 |
| DecoratedPublicKey | `addrStr(hash160(pubkey))[:12]` | yes (ADDRBYTE) | MSU:674-676 |
| Promissory note | `base58(hash256(concat(sorted(outpoints)) ‖ targetScript ‖ u64le(targetValue) ‖ changeScript_or_empty))[:8]` — **fee not included** | no | MSU:792-809 |
| USTX | `base58(hash256(unsignedPyTx.serialize()))[:8]` | no | TX:2010-2012 |

The same keys and M therefore produce different lockbox IDs on mainnet and
testnet. The lockbox ID is independent of key order and comments (see §1.4).

---

## 1. Lockbox (`MultiSigLockbox`)

### 1.1 Bare multisig script and key sorting

`pubkeylist_to_multisig_script(pkList, M, withSort=True)` (AU:1506-1529):

```
script = OP_M ‖ for pk in sorted(pkList): [len(pk) as 1 byte] ‖ pk ‖ OP_N ‖ OP_CHECKMULTISIG(0xae)
OP_k = 0x50 + k   (OP_1=0x51 … OP_16=0x60)
```

* Every key must be 33 or 65 bytes or `KeyDataError` (AU:1508-1509).
* **Sort #1 — script order:** lexicographic sort of raw pubkey bytes
  (Python `sorted` on `str`). Duplicate keys are allowed and kept
  (fixture `xxfz2Xk9` contains the same key twice, §6).
* Writers also sort the `DecoratedPublicKey` list by `binPubKey` before
  constructing the lockbox, so `dPubKeys[i]` ↔ script key i: GUI
  MSD:550, armoryd armoryd.py:2231-2237 (armoryd sorts the *hex strings*,
  equivalent for same-length lowercase hex).
* **The reader does not enforce sorted `dPubKeys`.** v1 `unserialize` rebuilds
  the script with sorting (MSU:411-412, and `setParams` MSU:296 again with
  `True`) but stores `dPubKeys`/`a160List` in file order (MSU:289-291).
  Signature *placement* does not depend on this (it matches by pubkey,
  TX:1227-1245, and the USTXI re-derives keys from the script). What breaks
  with an unsorted file is the review dialog: `evalSigStat` pairs `statusN[i]`
  (script order) with `wltSignRightNow[i]`/`wltOfflineSign[i]`, which are
  built from `lockbox.a160List[i]` (MSD:2570-2586, MSD:2966-3005), so the wrong
  key row would show as signed/signable. Rust: writers MUST emit sorted;
  readers SHOULD sort `dPubKeys` by `binPubKey` (stable, keeps comments attached).

C++ multisig recognition (`getMultisigPubKeyList`, BtcUtils.h:1124-1150):
last byte `0xae`; `script[0]` and `script[-2]` in `81..96`; then N pushes each
exactly `0x21` or `0x41` in size. Trailing bytes are not checked.

### 1.2 ScrAddr and lockbox ID

* **msScrAddr** (`getTxOutScrAddr` multisig branch → `getMultisigUniqueKey`,
  BtcUtils.h:1025-1029, 1076-1095):
  `0xfe ‖ u8(M) ‖ u8(N) ‖ concat(sorted(hash160(pk) for pk in script keys))`.
  Length `3 + 20·N`.
  **Sort #2 — scrAddr order:** sort by *hash160*, not by pubkey bytes. These
  orders differ in general (e.g. fixture `ZprWK4fA`, §6).
* **Lockbox ID** = `base58(hash160(MAGIC ‖ msScrAddr))[1:9]` (MSU:99-100).
  The slice `[1:9]` (drop char 0, take 8) is the fact; the source gives no
  reason (presumably the leading base58 digit of a 20-byte value is
  low-entropy — inference). `LOCKBOXIDSIZE = 8` (MSU:63).
* `calcLockboxID(script)` rejects non-multisig scripts (returns None,
  MSU:88-97). It is also used to identify a funding outpoint's lockbox
  (MSU:573) and in display strings `'Multisig %d-of-%d (%s)'` (MSU:72-75).

### 1.3 P2SH form

* `p2shScript = OP_HASH160 0x14 hash160(binScript) OP_EQUAL` = `a9 14 <20> 87`
  (AU:1476-1478).
* `p2shScrAddr = 0x05 ‖ hash160(binScript)` — ScrAddr prefix bytes are fixed
  (`0x00` P2PKH, `0x05` P2SH, `0xfe` multisig, `0xff` nonstd) regardless of
  network (AU:505-510, AU:1497-1504 comment).
* P2SH address string = `p2shAddrStr(hash160(binScript))`; prefix `3…` on
  mainnet, `2…` on testnet.
* Derived members set by `setParams` (MSU:278-304): `binScript`, `scrAddr`,
  `p2shScrAddr`, `uniqueIDB58`, `opStrList`, `a160List`, `asciiID = uniqueIDB58`.

### 1.4 Address-entry strings

`createLockboxEntryStr` / `readLockboxEntryStr` (MSU:63-121, 136-138):

* `Lockbox[<ID>]` → pay to the **P2SH** form.
* `Lockbox[Bare:<ID>]` → pay to the **bare** multisig script.
* `isP2SHLockbox` must exclude the Bare prefix (MSU:137-138; `'Lockbox['` is a
  prefix of `'Lockbox[Bare:'`). ID must be exactly 8 chars (MSU:115).
* Resolution to a script: `getScriptForUserString` (UserAddressUtils.py:61-70).
  A plain P2SH address that matches a known lockbox `p2shScrAddr` is also
  tagged with that lockbox (UserAddressUtils.py:91-95).

### 1.5 Binary serialization, version 1 (current writer)

`MultiSigLockbox.serialize` (MSU:308-321):

| Field | Type | Notes |
|---|---|---|
| version | UINT32 | always written as `MULTISIG_VERSION`=1 |
| magic | 4 bytes | network MAGIC |
| createDate | UINT64 | unix seconds (`long(RightNow())`, MSU:261) |
| shortName | VAR_STR | UTF-8 |
| longDescr | VAR_STR | UTF-8 |
| M | UINT8 | |
| N | UINT8 | |
| dPubKeys[i], i<N | VAR_STR | each = `DecoratedPublicKey.serialize()` (§2) |

No script is stored; it is rebuilt from the keys (MSU:411-412). Reader
(MSU:375-425): version≠1 only warns (MSU:398-401); magic mismatch raises
`NetworkIDError` unless `skipMagicCheck` (MSU:404-408); expectID mismatch
raises unless `skipMagicCheck` (MSU:416-420). Each embedded DPK is magic-checked
too (MSU:393-394). No trailing-byte check.

### 1.6 Binary serialization, version 0 (read-only legacy; all fixtures use it)

`unserialize_v0` (MSU:332-371), selected when the leading UINT32 is 0 (MSU:381-382):

| Field | Type |
|---|---|
| version | UINT32 = 0 |
| magic | 4 bytes |
| createDate | UINT64 |
| script | VAR_STR (the full bare multisig script) |
| shortName | VAR_STR |
| longDescr | VAR_STR |
| nComment | UINT32 |
| comments[i] | VAR_STR × nComment |

Keys come from the script (`getMultisigScriptInfo`, script order) and are
zipped with comments into DPKs (MSU:366-367). Note `unserialize` calls
`unserialize_v0(rawData, expectID)` **without** forwarding `skipMagicCheck`
(MSU:382), so a v0 lockbox from another network always fails. When ArmoryQt
loads lockboxes it rewrites `multisigs.txt` (§5), and `setParams` is called
without `version`, so v0 files are silently upgraded to v1 on first load.

### 1.7 JSON form (armoryd `getlockboxinfo`, `createlockbox`)

`toJSONMap` (MSU:431-454) keys: `version`, `magicbytes` (hex), `id`,
`lboxname`, `lboxdescr`, `M`, `N`, `pubkeylist` (list of DPK JSON, §2.3),
`a160list` (hex), `addrstrs`, `txoutscript` (hex bare script), `p2shscript`
(hex), `p2shaddr`, `createdate`. `fromJSONMap` (MSU:458-487) compares version
against `UNSIGNED_TX_VERSION` (harmless, both 1).

### 1.8 Behaviour helpers

* `isMofNNonStandardToSpend(m,n)` = `(n>3 and m>3) or (n>4 and m>2) or (n>5 and m>1) or n>6`
  (MSU:227-236) → warnings in the editor (MSD:584-596) and when sending to a
  P2SH lockbox (TxFrames.py:524-545). Text references Bitcoin Core 0.9.3/0.10.0
  standardness — historical.
* `createDecoratedTxOut(value, asP2SH)` (MSU:518-526): bare → `DTXO(binScript, value)`;
  P2SH → `DTXO(p2shScript, value, p2sh=binScript)`.
* `makeFundingTxFromPromNotes` (MSU:531-556) and `makeSpendingTx` (MSU:560-611):
  engine-level builders (§3.4, §4.1). The GUI does not call them.

### 1.9 Lockbox creation workflow (GUI) — `DlgLockboxEditor.doContinue` (MSD:480-606)

1. Require non-empty name; N pubkeys, each valid hex 33/65 (MSD:484-524).
2. Build `DecoratedPublicKey(pkBin, keyComment, *extras)` per row; warn on empty
   comments (MSD:526-545).
3. Sort DPKs by `binPubKey` (MSD:550); build script, ID (MSD:553-557).
4. If editing changed M/N/keys, warn that it becomes a different lockbox and
   reset `createDate` (MSD:558-573).
5. `MultiSigLockbox(name, descr, M, N, dPubKeys, createDate)`;
   `main.updateOrAddLockbox(lb, isFresh=True)` (persists to `multisigs.txt`,
   §5) and immediately show export dialog: default file
   `Lockbox_<ID>_.lockbox.def` (MSD:597-627).
6. Every other party imports the `=====LOCKBOX-…` block via
   `DlgImportLockbox` (MSD:2399-2478); a duplicate ID prompts overwrite.

armoryd `createlockbox M N <wltID|hex65>...` (armoryd.py:2120-2272): wallet
args contribute `getNextUnusedAddress().getPubKey()` (uncompressed); raw keys
must be 130-hex uncompressed (2203); sorts (2233); **DPKs are created without
comments** (2235) although names are computed; name `Lockbox <ID>`, descr
`<ID> - M-of-N - Created by armoryd`; appends to `multisigs.txt` and writes
`Lockbox_<ID>_.lockbox.def` in the home dir (2258-2263); returns `toJSONMap`.

---

## 2. DecoratedPublicKey (how a party shares a key)

### 2.1 Binary form (MSU:681-695; reader MSU:698-729)

| Field | Type | Notes |
|---|---|---|
| version | UINT32 | 1 |
| magic | 4 bytes | |
| binPubKey | VAR_STR | 33 (02/03) or 65 (04) bytes |
| keyComment | VAR_STR | UTF-8; free text, typically name/email/phone |
| wltLocator | VAR_STR | default `''` (reserved for BIP32 path hints) |
| authMethod | VAR_STR | default `''` |
| authData | VAR_STR | `NullAuthData.serialize()` = `''` (TX:1608-1622) |

`pubKeyID = addrStr(hash160(binPubKey))[:12]` (MSU:674-676) — the first 12
characters of the key's P2PKH address on the active network.

### 2.2 Exchange workflow

1. Each party opens "Select Public Key" (MSD:2151-2305), picks a key (address
   book with `getPubKey=True`) and types contact info. Validation: 33-byte keys
   must start `02/03`; 65-byte keys `04` and pass `VerifyPublicKeyValid`
   (MSD:2249-2264).
2. `DecoratedPublicKey(binPub, comment).serializeAscii()` →
   `=====PUBLICKEY-<pubKeyID>===…` block, exported via
   `DlgExportAsciiBlock` (save file default `PubKey_<pubKeyID>_.lockbox.pub`,
   MSD:2291-2292; clipboard; or `mailto:`).
3. The organizer imports each block into the lockbox editor ("Import" button
   per row, MSD:300-328) or pastes raw hex pubkeys; then clicks Continue
   (§1.9).

### 2.3 JSON (MSU:734-779)

`version`, `magicbytes`, `id`, `pubkeyhex`, `keycomment`, `wltLocator` (hex),
`authmethod`, `authdata` (hex). Bug: `fromJSONMap` compares the *hex* magic
string to binary `MAGIC_BYTES` (MSU:752, 762), so it only succeeds with
`skipMagicCheck=True` (which is how the tests call it, testMultisig.py:675).

---

## 3. Promissory notes and simulfunding

Purpose: several mutually distrusting parties fund one lockbox output in a
single transaction so that either everyone's coins move or nobody's
(MSD:1999-2008, MSD:1741-1766).

### 3.1 Binary form — `MultiSigPromissoryNote.serialize` (MSU:923-947)

| Field | Type | Notes |
|---|---|---|
| version | UINT32 | written as 1; fixtures contain **0** with identical layout — reader only warns (MSU:974-977); Rust MUST accept 0 and 1 |
| magic | 4 bytes | |
| dtxoTarget | VAR_STR | `DecoratedTxOut.serialize()` (§3.2) |
| dtxoChange | VAR_STR | DTXO bytes, or **empty** (len 0) when no change |
| feeAmt | UINT64 | this contributor's share of the fee, satoshi |
| numInputs | VAR_INT | |
| ustxInputs[i] | VAR_STR | `UnsignedTxInput.serialize()` (§4.2) |
| promLabel | VAR_STR | UTF-8 funder label |
| lockboxKey | VAR_STR | optional 33/65-byte pubkey (unused by UI; `setLockboxKey` MSU:907-919 never called) |

`promID` (MSU:792-809, `PROMIDSIZE=4` at MSU:64 is unused):
```
pre = concat(sorted(ustxi.outpoint.serialize() for ustxi in inputs))   # 36 bytes each: txHash(32, internal order) ‖ u32le idx
    ‖ dtxoTarget.binScript ‖ u64le(dtxoTarget.value)
    ‖ (dtxoChange.binScript if dtxoChange else b'')
promID = base58(hash256(pre))[:8]
```
`setParams` (MSU:860-903) also: stamps `ustxi.contribID = promID` on every
input (MSU:888-890); requires `sum(inputs) - (target.value + fee)` to equal
`dtxoChange.value` if positive, raises if negative (MSU:892-903). Note a
positive change with `dtxoChange=None` would crash with AttributeError.

JSON (MSU:1000-1075): `version, magicbytes, id, txouttarget, txoutchange ({} if none),
fee, numinputs, promlabel, lbpubkey` (raw bytes, not hex — bug), `inputs`
(omitted when `lite`). `fromJSONMap` has the same hex-vs-binary magic bug as
DPK (MSU:1042-1056).

### 3.2 DecoratedTxOut (DTXO) — TX:1625-1848

| Field | Type | Notes |
|---|---|---|
| version | UINT32 | 1 |
| magic | 4 bytes | |
| binScript | VAR_STR | the actual TxOut script |
| value | UINT64 | |
| p2shScript | VAR_STR | redeem script if known, else empty |
| wltLocator | VAR_STR | |
| authMethod | VAR_STR | default `'NONE'` (TX:1645) — 4 bytes `4e4f4e45` on the wire |
| authData | VAR_STR | `''` |
| contribID | VAR_STR | |
| contribLabel | VAR_STR | |

### 3.3 Simulfunding workflow (who does what, files exchanged)

Precondition: every party has imported the lockbox (§1.9) — needed to
recognise and display the target.

1. **Each funder — create note** (`DlgCreatePromNote.doContinue`, MSD:3305-3482;
   requires online BDM, MSD:3308-3316; only regular wallets, not lockboxes, can
   fund, MSD:3320-3333):
   * Target script from the address field — `Lockbox[<ID>]` → P2SH script;
     `dtxoTarget = DTXO(targetScript, amount)` (MSD:3413-3414).
   * Coin selection `PySelectCoins(utxos, amount, fee)` (MSD:3402).
   * Change → new P2PKH address in the funder's wallet (MSD:3420-3425).
   * One `UnsignedTxInput(rawSupportTx, idx, None, {scrAddr: pub65})` per
     selected UTXO (MSD:3430-3448) — includes the **full previous tx**.
   * `MultiSigPromissoryNote(dtxoTarget, fee, inputs, dtxoChange, label)`;
     export block `=====PROMISSORY-<promID>`, default file
     `Contrib_<promID>_<amountBTC>BTC.promnote` (MSD:3452-3476).
   * Nothing is signed; the note is not secret.
2. **Collector (any party) — merge** (`DlgMergePromNotes`, MSD:3485-3841):
   * Import notes (`DlgImportAsciiBlock` with `MultiSigPromissoryNote`,
     MSD:3638-3658) or create one in place (MSD:3661-3685).
   * Reject duplicates by promID (MSD:3690-3693). All notes must have the same
     target, compared after `reduceScript` maps bare multisig → its P2SH scrAddr
     (MSD:3697-3739, 3749-3754).
   * Optional "use bare multisig" checkbox if the target is a known lockbox
     (MSD:3713-3725): only `dtxoTarget.binScript` is replaced (MSD:3802-3804);
     the DTXO's `p2shScript`/`scrAddr` are not recomputed.
   * Build (MSD:3794-3822):
     * outputs: `[target(value = Σ note.target.value)]` + each note's change
       DTXO with `contribID = promID` (contribLabel **not** set);
     * inputs: each note's inputs in note-load order, with
       `contribID = promID` and `contribLabel = promLabel`;
     * `UnsignedTransaction().createFromUnsignedTxIO(inputs, outputs)`, locktime 0.
   * Opens `DlgMultiSpendReview` on it (MSD:3838-3839). (The
     `Simulfund_<ustxID>.sigcollect.tx` default name at MSD:3836 is dead in
     HEAD; review-dialog export uses `MultisigTransaction_<ID>_.sigcollect.tx`,
     MSD:3057. The fixture was produced by an older build using the former.)
3. **Every funder — review & sign**: import the `=====TXSIGCOLLECT-<ID>` block
   (lockbox manager "Review and Sign", MSD:1696-1712, or MSD:1774-1805, or
   main menu ArmoryQt.py:710-720), sign own P2PKH inputs, export, send back
   (§4).
4. **Collector — merge signatures, broadcast** (§4.3-§4.4). Because every input
   signs SIGHASH_ALL over all inputs and outputs, a funder's signature is
   useless unless the exact merged transaction is broadcast.

### 3.4 Engine variant `makeFundingTxFromPromNotes` (MSU:531-556)

Target output is always the **bare** script (`asP2SH=False`, MSU:538) with
value Σ targets; inputs in note order with `contribID` from `setParams`; change
outputs appended unless value 0; asserts `Σpay+Σfee == Σin−Σchange`.
Test vector: `NaVk9y4Y` (§7).

---

## 4. Spend workflow and signature collection

### 4.1 Creating the spend (USTX with multisig inputs)

GUI (`DlgSendBitcoins(spendFromLockboxID=…)` → `TxFrames.validateInputsGetUSTX`):

* UTXOs from the lockbox's C++ wallet (registered with both bare and P2SH
  scrAddrs, ArmoryQt.py:2985-2999).
* Fee estimate `calcMinSuggestedFeesHackMS`: `Σ(m·70+40) + 200·nRecipients`
  bytes (CoinSelection.py:762-792).
* Default change ("Feedback") goes to the lockbox **P2SH** script
  (TxFrames.py:887-899).
* Outputs shuffled (`random.shuffle`, TxFrames.py:732).
* `p2shMap = {hex(p2shScrAddr): binScript}`; `createFromTxOutSelection`
  (TxFrames.py:737-742 → TX:2099-2148 → `createFromPyTx` TX:2018-2095).
  **Quirk:** inputs look up `p2shMap` by *hex* scrAddr (TX:2071) but outputs by
  *binary* scrAddr (TX:2088), so output DTXOs to the lockbox never get
  `p2shScript` (all test vectors confirm `p2sh=''` on outputs).
* After construction, `contribID = lockboxID` is set on every input and on
  outputs whose script equals the bare script (TxFrames.py:744-749). This does
  not change the USTX ID.
* `DlgMultiSpendReview` opens (qtdialogs.py:5064-5071).

armoryd: `createlockboxustxtoaddress` / `createlockboxustxformany`
(armoryd.py:1095-1200) → `create_unsigned_transaction` (armoryd.py:1925-2016):
same p2shMap trick (1980-1983), change → lockbox P2SH (1991), returns
`serializeAscii()`; no contribID stamping.

Engine: `makeSpendingTx(rawFundTxIdxPairs, dtxoList, fee)` (MSU:560-611) checks
each funding output belongs to this lockbox (`calcLockboxID`, MSU:573), attaches
`binScript` as `p2shScript` for P2SH outputs, and adds change in the same form
(P2SH if any input was P2SH).

### 4.2 Wire formats

**UnsignedTxInput** (TX:1428-1450; reader TX:1456-1507):

| Field | Type | Notes |
|---|---|---|
| version | UINT32 | 1 |
| magic | 4 bytes | |
| outpoint | 36 bytes | `txHash(32, internal byte order) ‖ u32le(index)` |
| supportTx | VAR_STR | full serialized previous tx; reader requires `outpoint[:32]==hash256(supportTx)` (TX:1481-1482) |
| p2shScript | VAR_STR | redeem script for P2SH inputs, else empty |
| contribID | VAR_STR | promID or lockbox ID or empty |
| contribLabel | VAR_STR | UTF-8 |
| sequence | UINT32 | normally `0xffffffff` (warns otherwise) |
| nEntries | VAR_INT | = N (multisig) or 1 (single-sig) |
| per entry | VAR_STR pubKey, VAR_STR signature, VAR_STR wltLocator | signature empty = unsigned |

Derived on load (TX:957-1091): `txoScript`, `value` from supportTx;
for P2SH, verify `0x05‖hash160(p2shScript)` equals the output's scrAddr, and
take `scriptType` from the redeem script (TX:1033-1050). For multisig the
pubkey list is **re-derived from the script in script order** and `signatures`
are placed by entry index (TX:1067-1074, 1497-1505); the serialized pubkeys
are only used as a map for single-sig.

**UnsignedTransaction** (TX:2179-2203; reader TX:2206-2243):

| Field | Type |
|---|---|
| version | UINT32 = 1 |
| magic | 4 bytes |
| lockTime | UINT32 |
| nIn | VAR_INT |
| inputs | VAR_STR(USTXI) × nIn |
| nOut | VAR_INT |
| outputs | VAR_STR(DTXO) × nOut |

**USTX ID** (TX:1969-2012): build PyTx with `version = UNSIGNED_TX_VERSION (1)`,
inputs = (outpoint, empty scriptSig, sequence), outputs = (value, script),
`lockTime`; `ID = base58(hash256(serialize))[:8]`. Signatures, contrib
fields, p2sh scripts and support txs are **not** in the preimage, so every
partially signed copy of the same proposal has the same ID — this is the merge
key. (Note the tx version is 1 because `UNSIGNED_TX_VERSION` is reused as the
Bitcoin tx version, TX:1979, 2111.)

### 4.3 Signing

* Sighash: `generatePreHashTxMsgToSign` (TX:857-895) — copy tx, blank all
  scriptSigs, put `getTxoScriptToSign()` in the signed input, append
  `u32le(hashcode)`; only SIGHASH_ALL (1) allowed. `getTxoScriptToSign` =
  `p2shScript` if present else `txoScript` (TX:1314-1315), i.e. the **redeem
  script** for P2SH multisig.
* `createTxSignature` (TX:1194-1224): privkey must match one of `pubKeys`;
  deterministic k (RFC 6979) unless `--disable-detsign` (`ENABLE_DETSIGN`,
  AU:121-124, AU:279; EncryptionUtils.h:350); DER(r,s) ‖ hashcode byte.
* `insertSignature(sig, pub)` (TX:1227-1245) writes into **every** slot whose
  pubkey equals `pub` (duplicate keys in a lockbox get filled together).
* `insertSignatureForInput` (TX:2465-2472) verifies against each pubkey and
  stores at the matching index; `-1` if invalid.
* GUI per-key "Sign" buttons: `DlgMultiSpendReview.doSignForInput`
  (MSD:2917-2942) — for a lockbox bundle, signs every input of that bundle with
  the wallet key whose hash160 is `lockbox.a160List[keyIdx]` (MSD:2570-2586).
  Watch-only/offline wallets show "Offline": the user exports the block, signs
  in the same dialog on the offline machine, and brings it back.
* armoryd `signasciitransaction <file>` (armoryd.py:2021-2072, `sign_transaction`
  2080-2108): for each input recognised as the active lockbox, signs with every
  `a160List` key present in the active wallet; returns the ASCII USTX.

### 4.4 Signature status

`TXIN_SIGSTAT = ALREADY_SIGNED(0) < WLT_ALREADY_SIGNED(1) < WLT_CAN_SIGN(2) < NO_SIGNATURE(3)`
(TX:786-789). Per input: `statusN[i]` from non-empty signature / wallet
ownership; `statusM = sorted(statusN)[:M]`; `allSigned` iff `statusM[-1]` is
(WLT_)ALREADY_SIGNED (TX:1510-1546). USTX `canBroadcast` iff all inputs
`allSigned` (TX:2328-2369). This counts non-empty slots; it does not verify.

### 4.5 Merging signatures from several parties

`DlgMultiSpendReview.doImport` (MSD:3063-3089):

```
imported = UnsignedTransaction.unserializeAscii(text)
if current.uniqueIDB58 == imported.uniqueIDB58:
    for i, j over imported.ustxInputs[i].signatures[j]:
        if current.ustxInputs[i].signatures[j] non-empty:
            imported...signatures[j] = current...signatures[j]   # current wins
reopen the dialog on `imported`
```

* Merge is index-wise (input i, key slot j); slot union with the local copy
  taking precedence. **No signature verification at merge time.**
* If IDs differ, the imported USTX simply replaces the current one.
* Typical topology is star: organizer sends the block to each signer, each
  returns a copy with one more signature, organizer imports each copy in turn;
  chain topology (A→B→C) also works since each copy carries all prior sigs.

### 4.6 Finalization

`doBroadcast` (MSD:3092-3117) → `getSignedPyTx(doVerifySigs=True)`
(TX:2404-2431): require input order equal to pytx (TX:2381-2396), verify every
non-empty signature and require ≥M valid per input (`verifyAllSignatures`,
TX:1318-1338). On failure the GUI shows an error and **broadcasts anyway** with
`doVerifySigs=False` (MSD:3093-3105).

`createSigScript` (TX:1124-1191):
* normalises every signature to low-S/minimal DER (TX:1144-1151);
* multisig: `OP_0 ‖ push(sig) for each non-empty slot in key order`; if more
  than M sigs, pops **from the end of the slot list** until M remain
  (`stripExtraSigs`, TX:1168-1174) — empty slots are skipped, not pushed;
* P2SH: append `push(p2shScript)` (TX:1186-1189). `scriptPushData`
  (Script.py:82-94) uses a raw length byte for ≤76 (off-by-one: 76 should be
  PUSHDATA1, unreachable for multisig scripts), `0x4c` for ≤256, `0x4d` for
  ≤65536.

---

## 5. `multisigs.txt` storage

* Path `<ARMORY_HOME_DIR>/multisigs.txt` (AU:445-446); overridable with
  `--multisigFile` if the file exists (AU:450-453).
* Content: zero or more ASCII-armored LOCKBOX blocks.
  `writeLockboxesFile` (MSU:159-170): `'\n\n'.join(lb.serializeAscii()) + '\n'`,
  mode `'w'` (rewrite) or `'a'` (append), then `flush` + `fsync`. Serialization
  happens before opening the file.
* `readLockboxesFile` (MSU:175-205): split on every occurrence of the literal
  `=====LOCKBOX`; each slice is `.strip()`ped and parsed with
  `MultiSigLockbox().unserializeAscii`. Any exception aborts the whole read:
  the file is copied to `multisigs.txt.<unixtime>.bak` and the lockboxes parsed
  so far are returned (MSU:201-203). Blank lines, CRLF, and missing final
  newline are tolerated (fixture has all three variants, §6).
* ArmoryQt: loaded at startup **only in Expert user mode**
  (ArmoryQt.py:2861-2864). `loadLockboxesFromFile` → `updateOrAddLockbox` for
  each, which registers `[bareScrAddr, p2shScrAddr]` with the BDM as a pseudo
  wallet keyed by lockbox ID (ArmoryQt.py:2985-2999) and **rewrites the whole
  file** after every add/replace (ArmoryQt.py:3006) and remove (3020). This is
  how v0 entries become v1. Duplicate IDs: later replaces earlier in memory.
* armoryd: `getLockboxFilePaths` returns only `multisigs.txt` (MSU:209-224);
  `addMultLockboxes` keeps the first of duplicate IDs (armoryd.py:198-217);
  `createlockbox` appends (armoryd.py:2261-2262).
* Standalone exports: `Lockbox_<ID>_.lockbox.def` (one block + `'\n'`,
  MSD:2352-2357).

---

## 6. Fixture check (golden files)

Directory (session scratchpad, unpacked from the TIAB test fixture archive):
`/tmp/claude-0/-home-user-bitcoinarmory/a3b55be7-b74a-5b21-a2aa-6cd278fc969e/scratchpad/tiab/tiab/armory/`.
Decoder: Appendix A (self-contained Python 3, implements only §0–§4; it was
run on every file below and on every block in Appendix B). All files are CRLF, W=80 base64, testnet magic `0b110907`.

### 6.1 `multisigs.txt` — 4 lockboxes, all **version 0**, header ID == recomputed ID

| ID | M-of-N | created (UTC) | name | key slots (script order) | P2SH address |
|---|---|---|---|---|---|
| `xxfz2Xk9` | 2-of-3 | 1399999472 (2014-05-13 16:44:32) | `First Lockbox` | K2, K4, **K4** (duplicate) | `2NEGuMGuJ4meQsUCMYPT9qmCZtpXAKCicu4` |
| `YQR7xnZj` | 1-of-2 | 1400000815 (2014-05-13 17:06:55) | `Joint Account` | K2, K7 | `2N3pg4jUYNGxvZmay4SLSmNLPVi8oDf2CHG` |
| `rcEKCpQY` | 2-of-2 | 1400000863 (2014-05-13 17:07:43) | `Escrow` | K2, K7 | `2N8J15VSbNfAajBgmtpshbbcLDuZ3PrmTdD` |
| `ZprWK4fA` | 4-of-7 | 1400000915 (2014-05-13 17:08:35) | `Board of Directors` | K1…K7 | `2Mz6THSBFmLNGrMAqcdy3g8gpH6jrVBWqu7` |

All `longDescr` are empty; all scripts are already sorted; raw sizes 311, 241,
234, 722 bytes. `YQR7xnZj` and `rcEKCpQY` share keys but differ in M, hence
different IDs. `ZprWK4fA` is non-standard-to-spend per §1.8.

Keys (all uncompressed; comments from the v0 comment list):

| | pubkey (65 bytes hex) | hash160 | pubKeyID | comment |
|---|---|---|---|---|
| K1 | `040614710649234921d9474b63b1f58031ae68ac3d5ab6ae735941449d252ac6d5d42aa2d5494dabbaea006508cdbcaf8286b80493cd99ea30fdf601a278909d13` | `e305b80ba3a8da84886f13791b9bfc7dfff2a259` | `n2DLXxVZSNBf` | Secondary Wallet with a really r (vzgEfJrJ) |
| K2 | `04063eaf1596a02f4a29147aaf8ea732e8bc7e8dae712143b27f5b79b0342094d43128e863d1294379851bc76844fa6970fb33678fd24ea6824830afe5ef897408` | `9e73248c1e8a9540f0715e201349a730a710ccae` | `muxkzd4sitPb` | Primary Wallet (GDHFnMQ2) |
| K3 | `041ef9f1344e78a05d721a8c70769bb2641b1205c2056bf1faf681ddb004f719baf7314df3300e650938c2d4e77459abe55aeaa4fe9846089e305f981e5994b158` | `19b21a7e81c206b4975d985ecd08ff241a8f88f2` | `mhrpYhQLgYgA` | Primary Wallet (GDHFnMQ2) |
| K4 | `04201fe4fbd3312a4afbf2ac7f29cd26b93d8410e5fbadc178430afd93d7e54772dff4e719a201c110a5261b59ee502149e5a9c5d8365caa76c288858b3996a28e` | `4a54d83719d28c2ba24ef5e8c1208e412159f745` | `mnHywMYRuMyY` | Third Wallet (DZMmtb2v) |
| K5 | `0458fec9d580b0c6842cae00aecd96e89af3ff56f5be49dae425046e64057e0f499acc35ec10e1b544e0f01072296c6fa60a68ea515e59d24ff794cf8923cd30f4` | `8efe143a4fa3256a93ed481ca43cf10d8716c361` | `mtZ2d1jFZ9YN` | Primary Wallet (GDHFnMQ2) |
| K6 | `04a1eda09248fdd477141d591f5f1f6ce7207ea99716b0825b379f51589505457f2b17ad4373b0fb64c376798b5be72a86a69d23de51386517ad7ea40b9c3ca0a2` | `62d978319c7d7ac6cceed722c3d08aa81b371012` | `mpXd2u8fPVYd` | Third Wallet (DZMmtb2v) |
| K7 | `04d49ad61c8d61f9b1e83089602acbee0c1a79ed2ff4b2aa66b671ec1853575027b5e82cf499bf91acf477f46859e73ad869b8eb8f85e00702530a6049f43e97d9` | `d2f1cb6d6cee483b9c18c6ebfe371d37ad381b04` | `mzkKrXNPU6nf` | Secondary Wallet with a really r (vzgEfJrJ) |

ScrAddr examples (proving sort #2 is by hash160, not pubkey):

* `xxfz2Xk9`: `fe0203` ‖ `4a54…f745` ‖ `4a54…f745` ‖ `9e73…ccae` (K4,K4,K2 — opposite of script order K2,K4,K4).
* `ZprWK4fA`: `fe0407` ‖ K3 `19b2…` ‖ K4 `4a54…` ‖ K6 `62d9…` ‖ K5 `8efe…` ‖ K2 `9e73…` ‖ K7 `d2f1…` ‖ K1 `e305…`.

P2SH scripts: `xxfz2Xk9` → `a914e6abea43805995a9b88664bc3a948b043e8a3d1187`;
`YQR7xnZj` → `a9147404c097edba956ca1cf5044b0178dc12dfeda4787`;
`rcEKCpQY` → `a914a5105b94633835bc2cdd7e7cdca37a6c1d2da85b87`;
`ZprWK4fA` → `a9144b203c4b7b7f854588a142ac6aa2c71496be965587`.

### 6.2 Promissory notes — all **version 0** (v1 layout), ID == recomputed

| File | promID | label | target | fee | input (txid BE : idx, value) | change |
|---|---|---|---|---|---|---|
| `Contrib_J75shT7q_1BTC.promnote` | `J75shT7q` | FirstFunder | P2SH `2NEGuM…Cicu4` (= lockbox `xxfz2Xk9`), 1.0 BTC | 0.1 BTC | `c742fb5c…c0db:0`, 949.9998 BTC | 948.8998 BTC → `n3P9MQEv2GtK4RyEc48i2rbcBZnVkju4Nb` |
| `Contrib_4f71oDhA_1BTC.promnote` | `4f71oDhA` | SecondFunder | same, 1.0 BTC | 0.1 BTC | `c742fb5c…c0db:1`, 30 BTC | 28.9 BTC → `mk7pAQ7YdmnwWaGFCgwiKiEbaGjyEsSVUE` |
| `Contrib_3NFePKw5_1BTC.promnote` | `3NFePKw5` | ThirdFunder | same, 1.0 BTC | 0.1 BTC | `db0ee46b…eee4:0`, 20 BTC | 18.9 BTC → `msw6eseNASK8tGVdnQAPURFbHZaayt1pck` |

Each: one P2PKH input with one 65-byte pubkey and empty signature; input
`contribID` = promID, `contribLabel` empty; target DTXO `p2shScript` empty and
`authMethod='NONE'`; `lockboxKey` empty; `inputs == target + fee + change` holds.
Raw sizes 525/526/526 bytes. The filename amount is `coin2strNZS(1 BTC)` = `1`.

### 6.3 `Simulfund_fmuHCs5G.sigcollect.tx` — USTX v1, ID `fmuHCs5G` == recomputed

* 3 inputs, in note order 3NFePKw5, 4f71oDhA, J75shT7q; each `contribID`=promID
  and `contribLabel`=funder label (ThirdFunder/SecondFunder/FirstFunder); all
  signature slots empty (unsigned simulfund proposal).
* 4 outputs: target P2SH `2NEGuMGuJ4meQsUCMYPT9qmCZtpXAKCicu4` value 3.0 BTC
  (contribID empty); then the three change outputs with `contribID`=promID and
  empty contribLabel.
* fee = 0.3 BTC = Σ note fees. locktime 0. Exactly matches the
  `DlgMergePromNotes.mergeNotesCreateUSTX` construction in §3.3.

---

## 7. Test vectors (`pytest/testMultisig.py`)

All IDs below recompute with the §0.2 formulas using the Appendix A decoder.
All 15 ASCII blocks are reproduced verbatim in Appendix B (80-column, as in the
source), each labelled with its `testMultisig.py` line range.

### 7.1 Scalars

* `testUnsignedTx` (testMultisig.py:211-231): USTXI from `tx1raw` (33-41) output
  1 with pubkey `048d103d…c48b4b` (136-138); outputs P2PKH to hash160 of
  `mhyjJTq9RsDfhNdjTkga1CKhTiL5VFw85J` (1.00 BTC) and
  `mgoCqfR25kZVApAGFK3Tx5CTNcCppmKwfb` (0.49 BTC); expects
  `ustx.uniqueIDB58 == 'J2mRenD7'` (223). Verified.
* `testAddSigToUSTX` (239-256): `insertSignatureForInput(0, sigStr, pubKey) == 0`,
  without pubkey `== 0`, corrupted sig `== -1`. `sigStr` at 139-142.
* `testCreateMultisigTests` (260-397): privkeys `'\xaa'*32`, `'\xbb'*32`,
  `'\xcc'*32` (328); `pubkeylist_to_multisig_script(pubs,2) ==
  pubkeylist_to_multisig_script(pubs[::-1],2)` (335-337); for every subset of
  signers, `allSigned == (#signers > 1)`, `statusM[0]`, `statusM[1]` (364-375)
  and `canBroadcast == (#signers > 1)` (379-388). `signedFundMS` raw tx at
  308-322.
* `testCreateDecoratedTxOut` (780-796), lockbox `7mtvkCTa`, value 1000:
  bare script (784)
  `52410423214f61ebd268d190dbbe551f89151733af013e13e15bcdde65fd73421c90ba8bada58951154676acb616100a3885b2fdb2630f4737a2f1c0eebe79078129014104c594e7e0dff507907c8d22f9344d5e22269ce1b3a080325462a11296b6d2e37de6dede10dfa039a8a9a499866c5c507b0d02d4b4ea9549f80b8a1a348c0392ba4104ce15d8d12bfdbe86bd34578891165cc35cc4b42e5ddf4fea89f58487e75f48513b08be141e9ce0d13117975db7c999c0b150f8373764d0bcb5fb888d86468da353ae`,
  P2SH script (790) `a9149416dec5a7cdeb7a3baf0ba14f787532cc7e914287`,
  both `scriptType == CPP_TXOUT_MULTISIG`. Verified.
* `testMakeFundingTxFromPromNotes` (818-826): lockbox `7mtvkCTa` + promnote
  `GVfKYBqK` → 1 input, 1 output (bare script, 41170000 sat), ID `'NaVk9y4Y'` (826). Verified.
* `PubKeyBlockTest` (828-880): pubkey `048d103d…c48b4b`, comment
  `'This is a sample comment!'`, wltLoc `'Armory3cx8J2n#223'`,
  authMethod `'NullAuthMethod'` round-trip binary and ASCII.

### 7.2 ASCII blocks (`LockboxRelatedObjectsTest.setUpClass`, 412-661)

| Key | Lines | Header ID | Decoded |
|---|---|---|---|
| `dpk.nocomment` | 422-427 | `mqQQMsTsUyGJ` | v1, pub `04f5c848…`, all strings empty |
| `dpk.wcomment` | 429-434 | `mqjMCZC4BFRm` | v1, pub `0423214f…`, comment `this is a useless comment!@!` |
| `lockbox.nocomments` | 436-444 | `7mtvkCTa` | v1, 2-of-3, created 1403225125 (2014-06-20 00:45:25 UTC), name `Sample 2of3`; P2SH `2N6kFPiyJcgMxfFJpTF9wrDWVQCGnw5gaVM` |
| `lockbox.nometadata` | 446-455 | `7mtvkCTa` | same keys/ID; comments `Key #1 in the list`, `Key #2! `, `Key with unicode data!` — proves comments don't affect ID |
| `promnote.regular` (first) | 459-502 | `CerrVYjD` | v1, 3 P2PKH inputs (4990000+2990000+1780000), target P2SH `2N6VbMANSH7uHSQ8Sb4pRbfC3BANsfW664W` 9230000, fee 10000, change 520000, label `This is another testing comment` |
| `promnote.regular` (second) | 505-517 | `GVfKYBqK` | v1, 1 input 41170000, target P2SH of `7mtvkCTa` 41170000, fee 0, no change (empty VAR_STR), label `Dumping all my cash into this donation` |
| `ustx.regular` | 521-545 | `8rgLHcFg` | 2 P2PKH inputs, both signed (71, 72-byte sigs), 2 outputs, fee 10000 |
| `ustx.multispend_unsigned` | 548-566 | `7oXWAFds` | 1 P2SH input of `7mtvkCTa` (redeem script 201 B, contribID `7mtvkCTa`), sig slots [∅,∅,∅]; outputs 9990000 P2PKH + 10000000 change to lockbox P2SH (p2sh field empty) |
| `ustx.multispend_partsign` | 568-587 | `7oXWAFds` | slots [∅, 71 B, ∅] |
| `ustx.multispend_enoughsign` | 589-609 | `7oXWAFds` | slots [∅, 71 B, 72 B] (M=2 reached) |
| `ustx.multispend_oversign` | 611-632 | `7oXWAFds` | slots [72 B, 71 B, 72 B] (exercises `stripExtraSigs`) |
| `ustx.ss2ms_unsigned` | 634-646 | `HJqTvsXR` | P2PKH → 4000000 to lockbox P2SH + change |
| `ustx.ss2ms_signed` | 648-661 | `HJqTvsXR` | same, signed |

Notes:
* The second assignment to `serMap['promnote']['regular']` (505) overwrites the
  first (459); only `GVfKYBqK` is exercised by tests, but `CerrVYjD` is a valid
  vector too.
* The four `7oXWAFds` blocks prove the USTX ID excludes signatures (§4.2) and
  give a ready-made merge test: merging partsign + {sign slot 2} → enoughsign.
* Round-trip tests (`doRoundTrip`, 664-681) compare objects via `EQ_ATTRS_*`
  and call with `skipMagicCheck=True` (testnet data under any network).
* `asc_nosig` / `asc_sig` (269-284, 287-303; header `5JxmLy4T`) are a
  **pre-release layout**: USTXI has no `contribLabel` (only p2sh, contribID
  before sequence) and DTXO has no `contribID`/`contribLabel`. Current code
  cannot parse them and no active assertion does (324-325 are commented out).
  The USTX ID formula still reproduces `5JxmLy4T` from the decoded tx.
  Exclude from Rust conformance tests.

---

## 8. Dependencies on dead / legacy infrastructure

| Feature | What it uses | Source | Rust recommendation |
|---|---|---|---|
| armoryd `sendlockbox lbIDs sender server pwd recips [subj]` | `@EmailOutput` → `send_email`: `smtplib.SMTP(host, port=587)`, `ehlo/starttls/login(sender, pwd)`, password passed as a CLI/RPC argument in plaintext | armoryd.py:2413-2455, Decorators.py:25-35, AU:3391-3419 | Drop; export ASCII blocks to stdout/file instead |
| armoryd `watchwallet` (same email path) | same | armoryd.py:2348-2400 | Drop |
| GUI "Send Email" buttons | `mailto:?subject=…&body=…` via `QDesktopServices.openUrl`; EMAILSUBJ/EMAILBODY per class | MSD:2368-2396; MSU:244-252, 620-627, 819-827; TX:1935-1945 | Optional; clipboard/file are sufficient |
| Lockbox balance/history, UTXO lookup, prom-note coin selection | `TheBDM.registerLockbox(id, [bare, p2sh scrAddrs])`, C++ LevelDB BDM (Armory 0.92/0.93 era) | MSU:273-274, ArmoryQt.py:2985-2999, armoryd.py:2979-2988 | Replace with the new chain backend; watch both scrAddrs |
| `hash160`, `script_to_scrAddr`, `getMultisigPubKeyInfoStr`, ECDSA | SWIG `Cpp.BtcUtils` / `CryptoECDSA` | AU:1555-1557, AU:1818-1820, TX:344 | Native Rust (secp256k1, ripemd) |
| Standardness warnings | Bitcoin Core 0.9.3 / 0.10.0 bare/P2SH limits | MSD:584-596, TxFrames.py:516-545 | Re-evaluate (P2SH ≤15 keys, 520-byte redeem script) |
| Explorer links | blockchain.info / blockexplorer.com | AU:485-500 | Configurable |
| `ui/MultiSigModels.getKeyDisp` (MultiSigModels.py:41-47) | references `lbox.commentList`/`lbox.pkList`, which no longer exist | MSU:278-304 (no such members) | Stale code; use `dPubKeys[i].keyComment` |
| Fee estimation | `calcMinSuggestedFeesHackMS` heuristics, `estimateFee()` | CoinSelection.py:762-792 | Replace |
| Wallet locators / authMethod / authData | Always empty / `NullAuthData` / `'NONE'`; reserved for BIP32 & X.509 ideas never shipped | TX:1608-1622, TX:1626-1638 | Preserve bytes on round-trip; no semantics |

Everything else (all binary/ASCII formats, IDs, simulfunding merge, signature
merge, sig-script construction) is self-contained and portable.

---

## 9. Implementation checklist for Rust

1. Parse lockbox v0 and v1; always write v1. Reject or normalize unsorted keys.
2. Implement the four ID formulas exactly (§0.2) including `[1:9]` vs `[:8]`
   and network dependence of lockbox and DPK IDs.
3. Two sort orders: pubkey bytes for the script, hash160 for the scrAddr.
4. ASCII reader: whitespace-split, width/CRLF agnostic; check BLKSTRING (fixing
   the Python bug); check header ID uniformly.
5. Promissory version 0 accepted. Empty change VAR_STR ⇒ no change.
6. USTX merge keyed by USTX ID; union of signature slots; verify signatures
   before broadcast (do not replicate the "broadcast anyway" fallback silently).
7. Sig-script: low-S DER, OP_0 + first-M non-empty sigs in key order, push
   redeem script for P2SH with correct PUSHDATA sizing.
8. `multisigs.txt`: blocks separated by blank line, trailing `\n`, atomic
   rewrite; on parse error back up as `.<unixtime>.bak`.

---

## Appendix A — reference decoder (Python 3, self-contained)

Written from this spec (not from Armory code). Run as
`python3 decoder.py multisigs.txt *.promnote *.sigcollect.tx`; prints
`<file> <KIND> <headerID> <recomputedID> OK|MISMATCH`. Output on the §6
fixtures: 8/8 OK. Every Appendix B block except the two legacy ones also
decodes with recomputed ID == header ID.

```python
import base64, hashlib, struct, sys, os, re, datetime, json

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TESTNET_MAGIC = bytes.fromhex('0b110907')
MAINNET_MAGIC = bytes.fromhex('f9beb4d9')
NET = {TESTNET_MAGIC: dict(name='testnet', addr=b'\x6f', p2sh=b'\xc4'),
       MAINNET_MAGIC: dict(name='mainnet', addr=b'\x00', p2sh=b'\x05')}

def sha256(b): return hashlib.sha256(b).digest()
def hash256(b): return sha256(sha256(b))
def hash160(b): return hashlib.new('ripemd160', sha256(b)).digest()

def b58(b):
    pad = len(b) - len(b.lstrip(b'\x00'))
    n = int.from_bytes(b, 'big'); s = ''
    while n > 0:
        n, r = divmod(n, 58); s = B58[r] + s
    return '1' * pad + s

def b58check(ver, payload):
    d = ver + payload
    return b58(d + hash256(d)[:4])

class R:
    def __init__(s, b): s.b, s.p = b, 0
    def take(s, n):
        if s.p + n > len(s.b): raise ValueError('underrun')
        v = s.b[s.p:s.p+n]; s.p += n; return v
    def u8(s): return s.take(1)[0]
    def u32(s): return struct.unpack('<I', s.take(4))[0]
    def u64(s): return struct.unpack('<Q', s.take(8))[0]
    def vi(s):
        c = s.u8()
        if c < 0xfd: return c
        return {0xfd: lambda: struct.unpack('<H', s.take(2))[0],
                0xfe: s.u32, 0xff: s.u64}[c]()
    def vs(s): return s.take(s.vi())
    def rem(s): return len(s.b) - s.p

def read_ascii_block(txt):
    toks = txt.strip().split()
    assert toks[0].startswith('=====') and toks[-1].startswith('======')
    head = toks[0].strip('=')
    return head, base64.b64decode(''.join(toks[1:-1]))

def split_blocks(all_text, mark):
    out, pos = [], all_text.find(mark)
    while pos >= 0:
        nxt = all_text.find(mark, pos + 1)
        out.append(all_text[pos: nxt if nxt >= 0 else len(all_text)].strip())
        pos = nxt
    return out

# ---------- scripts ----------
def parse_multisig(script):
    if script[-1] != 0xae: return None
    M, N = script[0], script[-2]
    if not (81 <= M <= 96 and 81 <= N <= 96): return None
    M -= 80; N -= 80
    p, pubs = 1, []
    for _ in range(N):
        sz = script[p]; p += 1
        if sz not in (0x21, 0x41): return None
        pubs.append(script[p:p+sz]); p += sz
    return M, N, pubs

def make_multisig(pubs, M, sort=True):
    pk = sorted(pubs) if sort else list(pubs)
    return bytes([80+M]) + b''.join(bytes([len(k)]) + k for k in pk) + bytes([80+len(pk), 0xae])

def ms_scraddr(script):
    M, N, pubs = parse_multisig(script)
    return b'\xfe' + bytes([M, N]) + b''.join(sorted(hash160(k) for k in pubs))

def lockbox_id(script, magic):
    return b58(hash160(magic + ms_scraddr(script)))[1:9]

def p2sh_script(script): return b'\xa9\x14' + hash160(script) + b'\x87'

def script_desc(script, net):
    if len(script) == 25 and script[:3] == b'\x76\xa9\x14' and script[-2:] == b'\x88\xac':
        return 'P2PKH ' + b58check(net['addr'], script[3:23])
    if len(script) == 23 and script[:2] == b'\xa9\x14' and script[-1] == 0x87:
        return 'P2SH ' + b58check(net['p2sh'], script[2:22])
    ms = parse_multisig(script)
    if ms: return 'MULTISIG %d-of-%d' % (ms[0], ms[1])
    return 'NONSTD ' + script.hex()

# ---------- objects ----------
def parse_dpk(raw):
    r = R(raw)
    d = dict(version=r.u32(), magic=r.take(4).hex(), pub=r.vs(), comment=r.vs(),
             wltLoc=r.vs(), authMethod=r.vs(), authData=r.vs())
    assert r.rem() == 0
    return d

def dpk_id(pub, net): return b58check(net['addr'], hash160(pub))[:12]

def parse_lockbox(raw):
    r = R(raw)
    ver = r.u32(); magic = r.take(4); created = r.u64()
    if ver == 0:
        script = r.vs(); name = r.vs(); descr = r.vs(); nc = r.u32()
        comments = [r.vs() for _ in range(nc)]
        M, N, pubs = parse_multisig(script)
        dpks = [dict(pub=p, comment=c) for p, c in zip(pubs, comments)]
    else:
        name = r.vs(); descr = r.vs(); M = r.u8(); N = r.u8()
        dpks = []
        for _ in range(N):
            d = parse_dpk(r.vs()); dpks.append(d)
        script = make_multisig([d['pub'] for d in dpks], M)
    assert r.rem() == 0, 'trailing bytes'
    return dict(version=ver, magic=magic, created=created, name=name,
                descr=descr, M=M, N=N, dpks=dpks, script=script)

def outpoint_ser(txhash, idx): return txhash + struct.pack('<I', idx)

def parse_pytx(raw):
    r = R(raw); ver = r.u32(); ins = []; outs = []
    for _ in range(r.vi()):
        op = r.take(36); scr = r.vs(); seq = r.u32(); ins.append((op, scr, seq))
    for _ in range(r.vi()):
        v = r.u64(); s = r.vs(); outs.append((v, s))
    lt = r.u32(); assert r.rem() == 0
    return dict(version=ver, ins=ins, outs=outs, locktime=lt)

def parse_ustxi(raw):
    r = R(raw)
    d = dict(version=r.u32(), magic=r.take(4), outpoint=r.take(36), supportTx=r.vs(),
             p2sh=r.vs(), contribID=r.vs(), contribLabel=r.vs(), seq=r.u32())
    n = r.vi(); d['keys'] = []
    for _ in range(n):
        d['keys'].append(dict(pub=r.vs(), sig=r.vs(), loc=r.vs()))
    assert r.rem() == 0
    assert d['outpoint'][:32] == hash256(d['supportTx']), 'outpoint hash != hash256(supportTx)'
    idx = struct.unpack('<I', d['outpoint'][32:])[0]
    tx = parse_pytx(d['supportTx'])
    d['value'], d['txoScript'] = tx['outs'][idx]
    d['idx'] = idx
    return d

def parse_dtxo(raw):
    r = R(raw)
    d = dict(version=r.u32(), magic=r.take(4), script=r.vs(), value=r.u64(), p2sh=r.vs(),
             wltLoc=r.vs(), authMethod=r.vs(), authData=r.vs(), contribID=r.vs(),
             contribLabel=r.vs())
    assert r.rem() == 0
    return d

def parse_promnote(raw):
    r = R(raw)
    d = dict(version=r.u32(), magic=r.take(4))
    d['target'] = parse_dtxo(r.vs())
    ch = r.vs(); d['change'] = parse_dtxo(ch) if ch else None
    d['fee'] = r.u64()
    d['inputs'] = [parse_ustxi(r.vs()) for _ in range(r.vi())]
    d['label'] = r.vs(); d['lbKey'] = r.vs()
    assert r.rem() == 0
    return d

def prom_id(p):
    ops = sorted(u['outpoint'] for u in p['inputs'])
    t = p['target']['script'] + struct.pack('<Q', p['target']['value'])
    t += p['change']['script'] if p['change'] else b''
    return b58(hash256(b''.join(ops) + t))[:8]

def parse_ustx(raw):
    r = R(raw)
    d = dict(version=r.u32(), magic=r.take(4), locktime=r.u32())
    d['inputs'] = [parse_ustxi(r.vs()) for _ in range(r.vi())]
    d['outputs'] = [parse_dtxo(r.vs()) for _ in range(r.vi())]
    assert r.rem() == 0
    return d

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def ustx_id(u):
    # PyTx with version=UNSIGNED_TX_VERSION(1), empty scriptSigs, real sequences
    b = struct.pack('<I', 1) + varint(len(u['inputs']))
    for i in u['inputs']:
        b += i['outpoint'] + varint(0) + struct.pack('<I', i['seq'])
    b += varint(len(u['outputs']))
    for o in u['outputs']:
        b += struct.pack('<Q', o['value']) + varint(len(o['script'])) + o['script']
    b += struct.pack('<I', u['locktime'])
    return b58(hash256(b))[:8]

def decode_block(txt):
    """Parse one ASCII block; return (kind, header_id, recomputed_id, obj)."""
    head, raw = read_ascii_block(txt)
    kind, hid = head.split('-')[0], head.split('-')[-1]
    if kind == 'LOCKBOX':
        o = parse_lockbox(raw); cid = lockbox_id(o['script'], o['magic'])
    elif kind == 'PUBLICKEY':
        o = parse_dpk(raw); cid = dpk_id(o['pub'], NET[bytes.fromhex(o['magic'])])
    elif kind == 'PROMISSORY':
        o = parse_promnote(raw); cid = prom_id(o)
    elif kind == 'TXSIGCOLLECT':
        o = parse_ustx(raw); cid = ustx_id(o)
    else:
        raise ValueError(kind)
    return kind, hid, cid, o

if __name__ == '__main__':
    import sys
    for path in sys.argv[1:]:
        txt = open(path, 'rb').read().decode('utf-8')
        blocks = split_blocks(txt, '=====LOCKBOX') if '=====LOCKBOX' in txt else [txt]
        for b in blocks:
            kind, hid, cid, o = decode_block(b)
            print(path, kind, hid, cid, 'OK' if hid == cid else 'MISMATCH')
```

## Appendix B — verbatim test vectors from `pytest/testMultisig.py`

Copied byte-for-byte (indentation removed by `textwrap.dedent`, as the test
does). Line ranges are the block lines in the source file.

### `asc_nosig` — testMultisig.py:270-283 — **legacy pre-release layout, excluded from conformance** (§7.2)

```
=====TXSIGCOLLECT-5JxmLy4T======================================================
AQAAAAsRCQcAAAAAAf19AQEAAAALEQkH/XsoFKgwJMVZsviXpv+aOun4BQHRm+Cuvs/X7O/J3n8BAAAA
/QMBAQAAAAGcgxlJ0d+ZHi+MzG+laL4qTx/jVH/lPbbKmrGLA1oc8AAAAACMSTBGAiEArOklwdcihg72
fMu+GvnKF+AdFiMmeT7CWV4KMZmA3kcCIQDyjBMqkI6tFVXMG/yhbBhVg7TNYsAGLjM5UWLfVx57WgFB
BLmTMVBhjWo901GrcZzZMNBUectdX4ZsVyHhMNjZpaAJxlpQqnjiK9PAvrNqOIgMq8itz9S3KDaOs/Kh
W6/lJNL/////AsAOFgIAAAAAGXapFInbjSGPxqYLm35NTXhzcAkVf8h8iKwwq98DAAAAABl2qRSBj0Gs
NlhCyvZkoRO2iRw54544foisAAAAAAAA/////wFBBJ6i78WXHp6ywhTupFpF7A0V2jwQEjE9pWO1+7wZ
qS+IM59Dur1Ut5OC+yUycjeFHQdqemkBDFT97zMCJalmtXwAAALiAQAAAAsRCQfJUkEEagSrmNnkd0rY
BuMC3d62O+oWtctfIj7ndHjoYbtYPrM2tvvLYLWz1PFVGsReX/xJNkZufZj2x8Dsc2U590aRpkEEaGgH
N8dtq7gByyIE9X2+TkV55PcQzWfcG0InWSyB6bXPArWsnotMn0m+UlEFa2ptAR5MN/a20X7ea1X6ojUZ
4kEEuVwknYT0F+PjlaEnQlQotUBnHMFYgeuCjBe3IqU/xZniHKXlbJDzQJiNOTOsx2vrgy/WTKsHjd88
5zKSMDHRqFOuoH+IAgAAAAAAAAROT05FADIBAAAACxEJBxl2qRRs7kd5CHIvdApqfOmMDp1dyrD6Mois
gARXAQAAAAAAAAROT05FAA==
================================================================================
```

### `asc_sig` — testMultisig.py:288-302 — **legacy pre-release layout, excluded from conformance** (§7.2)

```
=====TXSIGCOLLECT-5JxmLy4T======================================================
AQAAAAsRCQcAAAAAAf3EAQEAAAALEQkH/XsoFKgwJMVZsviXpv+aOun4BQHRm+Cuvs/X7O/J3n8BAAAA
/QMBAQAAAAGcgxlJ0d+ZHi+MzG+laL4qTx/jVH/lPbbKmrGLA1oc8AAAAACMSTBGAiEArOklwdcihg72
fMu+GvnKF+AdFiMmeT7CWV4KMZmA3kcCIQDyjBMqkI6tFVXMG/yhbBhVg7TNYsAGLjM5UWLfVx57WgFB
BLmTMVBhjWo901GrcZzZMNBUectdX4ZsVyHhMNjZpaAJxlpQqnjiK9PAvrNqOIgMq8itz9S3KDaOs/Kh
W6/lJNL/////AsAOFgIAAAAAGXapFInbjSGPxqYLm35NTXhzcAkVf8h8iKwwq98DAAAAABl2qRSBj0Gs
NlhCyvZkoRO2iRw54544foisAAAAAAAA/////wFBBJ6i78WXHp6ywhTupFpF7A0V2jwQEjE9pWO1+7wZ
qS+IM59Dur1Ut5OC+yUycjeFHQdqemkBDFT97zMCJalmtXxHMEQCIF12j4Vj1Shf49BkDWwVzf1kRgYr
4EIPObgRTVPQz2KkAiAQ28gOniv2A5ozeBCk/rpWHTw2DqqkraEUDYLAPr83NQEAAuIBAAAACxEJB8lS
QQRqBKuY2eR3StgG4wLd3rY76ha1y18iPud0eOhhu1g+sza2+8tgtbPU8VUaxF5f/Ek2Rm59mPbHwOxz
ZTn3RpGmQQRoaAc3x22ruAHLIgT1fb5ORXnk9xDNZ9wbQidZLIHptc8Ctayei0yfSb5SUQVram0BHkw3
9rbRft5rVfqiNRniQQS5XCSdhPQX4+OVoSdCVCi1QGccwViB64KMF7cipT/FmeIcpeVskPNAmI05M6zH
a+uDL9ZMqweN3zznMpIwMdGoU66gf4gCAAAAAAAABE5PTkUAMgEAAAALEQkHGXapFGzuR3kIci90Cmp8
6YwOnV3KsPoyiKyABFcBAAAAAAAABE5PTkUA
================================================================================
```

### `dpk.nocomment` — testMultisig.py:423-426

```
=====PUBLICKEY-mqQQMsTsUyGJ=====================================================
AQAAAAsRCQdBBPXISLf5jl7LafjFYbMVfb+OqjzMD8XGVyBauZ1kNA/tMGoZn5lHdfZRVcNN8D9+9vG9
GpvTn9PUWZ1uETTewPIAAAAA
================================================================================
```

### `dpk.wcomment` — testMultisig.py:430-433

```
=====PUBLICKEY-mqjMCZC4BFRm=====================================================
AQAAAAsRCQdBBCMhT2Hr0mjRkNu+VR+JFRczrwE+E+Fbzd5l/XNCHJC6i62liVEVRnasthYQCjiFsv2y
Yw9HN6LxwO6+eQeBKQEcdGhpcyBpcyBhIHVzZWxlc3MgY29tbWVudCFAIQAAAA==
================================================================================
```

### `lockbox.nocomments` — testMultisig.py:437-443

```
=====LOCKBOX-7mtvkCTa===========================================================
AQAAAAsRCQclhKNTAAAAAAtTYW1wbGUgMm9mMwACA04BAAAACxEJB0EEIyFPYevSaNGQ275VH4kVFzOv
AT4T4VvN3mX9c0IckLqLraWJURVGdqy2FhAKOIWy/bJjD0c3ovHA7r55B4EpAQAAAABOAQAAAAsRCQdB
BMWU5+Df9QeQfI0i+TRNXiImnOGzoIAyVGKhEpa20uN95t7eEN+gOaippJmGbFxQew0C1LTqlUn4C4oa
NIwDkroAAAAATgEAAAALEQkHQQTOFdjRK/2+hr00V4iRFlzDXMS0Ll3fT+qJ9YSH519IUTsIvhQenODR
MReXXbfJmcCxUPg3N2TQvLX7iI2GRo2jAAAAAA==
================================================================================
```

### `lockbox.nometadata` — testMultisig.py:447-454

```
=====LOCKBOX-7mtvkCTa===========================================================
AQAAAAsRCQclhKNTAAAAAAtTYW1wbGUgMm9mMwACA2ABAAAACxEJB0EEIyFPYevSaNGQ275VH4kVFzOv
AT4T4VvN3mX9c0IckLqLraWJURVGdqy2FhAKOIWy/bJjD0c3ovHA7r55B4EpARJLZXkgIzEgaW4gdGhl
IGxpc3QAAABWAQAAAAsRCQdBBMWU5+Df9QeQfI0i+TRNXiImnOGzoIAyVGKhEpa20uN95t7eEN+gOaip
pJmGbFxQew0C1LTqlUn4C4oaNIwDkroIS2V5ICMyISAAAABkAQAAAAsRCQdBBM4V2NEr/b6GvTRXiJEW
XMNcxLQuXd9P6on1hIfnX0hROwi+FB6c4NExF5ddt8mZwLFQ+Dc3ZNC8tfuIjYZGjaMWS2V5IHdpdGgg
dW5pY29kZSBkYXRhIQAAAA==
================================================================================
```

### `promnote.regular` — testMultisig.py:460-501 (first assignment; overwritten at runtime by the next one)

```
=====PROMISSORY-CerrVYjD========================================================
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
IHRlc3RpbmcgY29tbWVudAA=
================================================================================
```

### `promnote.regular` — testMultisig.py:506-516 (second assignment; the one the tests use)

```
=====PROMISSORY-GVfKYBqK========================================================
AQAAAAsRCQcyAQAAAAsRCQcXqRSUFt7Fp83rejuvC6FPeHUyzH6RQodQNHQCAAAAAAAABE5PTkUAAAAA
AAAAAAAAAAAB/YMBAQAAAAsRCQdKjCQZ04S5mekJ7FSvGyohppsRllgQ1lF0D/ewX9Ls6AAAAAD9AAEB
AAAAATS/9KXacFYJPYQCoSkRSIKYDIIgQ6wZzEdgiipEAVbuAAAAAItIMEUCIE9MTdfNrRrMW8BFe8uC
N34DMz3wYa+KL6bPkxNpgDUnAiEAnfZxXXfhAdF435vRb1kWxg65NbMAHfbX/bDh9iXQNKYBQQRBul/I
mA3bgs0PGSJFd3KeQPBPp9LYuduFgnfA+kEKf1GZI4s+EGuxDHvjZoNBwYvWPEgtqYVxvybEXWHwhhou
/////wJQNHQCAAAAABl2qRSSFcygbZulF1EFISvxCYhFoLBf44isAC0xAQAAAAAXqRSUFt7Fp83rejuv
C6FPeHUyzH6RQocAAAAAAAhHVmZLWUJxSwD/////AUEEBgLRFKodcJB0fSX3gNeaAM7uNQNM/tL8RcBZ
4+5P1i6RbjURO9yt34sF0flB8XbiR/T/cUqkn66p/S/Ww3FKEwAAJkR1bXBpbmcgYWxsIG15IGNhc2gg
aW50byB0aGlzIGRvbmF0aW9uAA==
================================================================================
```

### `ustx.regular` — testMultisig.py:522-544

```
=====TXSIGCOLLECT-8rgLHcFg======================================================
AQAAAAsRCQcAAAAAAv3EAQEAAAALEQkHc4uuUlna6Cw/HRowBY70IQ52kRVtRw8FNAIkl8SsT7kBAAAA
/QIBAQAAAAEXA5J+qKVnY8IE4dDBE58Pyp+q1uA/RBkeol1FLLoZFQAAAACLSDBFAiEA0dB7emFmICZD
NecZeg7eRzjjOKTmg+EZLXca14dg1uYCIBDnAgPWPSMmwaK5ZWpTeCuhn86qDh1KyP87cglKYhWdAUEE
UtPQusiUYHM/ECQT0yg2oqwdYUsUmer4RyxxD0lxRei8AceGdrnDC5uL/Y6kzW3rQxynEVXBGJI01Qkk
1frDLP////8CMBsPAAAAAAAZdqkUOW5GJnPKcmK1r9T5oiPKqWm0HSGIrICWmAAAAAAAGXapFHAJXqNd
6fuLln4Tkl6tDx7sbO/giKwAAAAAAAAA/////wFBBCMhT2Hr0mjRkNu+VR+JFRczrwE+E+Fbzd5l/XNC
HJC6i62liVEVRnasthYQCjiFsv2yYw9HN6LxwO6+eQeBKQFHMEQCIFlfw+VSIaBS6vDXbs093+fNaFJb
3GidWizy+UUAhHXZAiAXwqBQPrg2zXMo/VOkEpKlHAHccv2/laZJdwRCE+BnAgEA/ZoCAQAAAAsRCQcR
yZHa7iCRLwdDH0oHdiOvbDVj5cDoexX5HK0fFh8RvAIAAAD91wEBAAAAAqSzhO8p2UlTYZbBtnV3nyrq
rfShMZfzDpIdLcm6AQPzAQAAAItIMEUCIQCREoEDVTRz2WqLHbLnDYKpTUhgufQ7je76GxYCyppdGAIg
HEhwzPsLCdraLY/mBMqotfTE6SPowHeo6LFuH9GYX00BQQRWZgMKp8HBmppMCu35YERTSJSu4EO99s/R
Q3+jtZINL8XO1XY1S8UM7/ajjM6Wv3g45bGjATcKtGwqhAlIWl1e/////yvlXmEhjTLSBnhishefOy0R
ldxN3AlytJ2VYlYq1inMAQAAAIxJMEYCIQDqUpfjjR1xuMh2/7cXzSh7cZXOBM0IxpKEaSrXDKvdEgIh
AKwM/OsjuRcgq6KXyZ0swmVx8o/dGgbCPYCkj2ZI4wweAUEEzhXY0Sv9voa9NFeIkRZcw1zEtC5d30/q
ifWEh+dfSFE7CL4UHpzg0TEXl123yZnAsVD4Nzdk0Ly1+4iNhkaNo/////8DQIr3AQAAAAAXqRSRUUn/
7EjvozN4YtftMtBnm438H4fArNgAAAAAABl2qRSfOjzmZuGGa8CNGDprHfriVETn2IisICkbAAAAAAAZ
dqkUbZs27Nt1uzK2C61o8v2KMbWTJx6IrAAAAAAAAAD/////AUEEId3cF/ZIV3rHris7l19HJqGvR4ED
HTttl5rxyll0y92LflGgmMdMKHnX6CqOKYS0KJljBV0WaFD0gCcdnaUodkgwRQIgI0xQLY+qnQKi8f65
5OEAPEv/r0rZnLB/h7qd5LF6hm8CIQCOPpmt1Jr6o1b43VEYg0PNKYzRekLppI3gpVFh0zlM2AEAAjQB
AAAACxEJBxl2qRQWtJ1IcK7dFugwnF1pwaCGOsMI1oisgJaYAAAAAAAAAAROT05FAAAANAEAAAALEQkH
GXapFFwtg57h8JGhIbsJLXk23+KqzOo9iKwQAhsAAAAAAAAABE5PTkUAAAA=
================================================================================
```

### `ustx.multispend_unsigned` — testMultisig.py:549-565

```
=====TXSIGCOLLECT-7oXWAFds======================================================
AQAAAAsRCQcAAAAAAf3UAgEAAAALEQkHSowkGdOEuZnpCexUrxsqIaabEZZYENZRdA/3sF/S7OgBAAAA
/QABAQAAAAE0v/Sl2nBWCT2EAqEpEUiCmAyCIEOsGcxHYIoqRAFW7gAAAACLSDBFAiBPTE3Xza0azFvA
RXvLgjd+AzM98GGvii+mz5MTaYA1JwIhAJ32cV134QHReN+b0W9ZFsYOuTWzAB321/2w4fYl0DSmAUEE
QbpfyJgN24LNDxkiRXdynkDwT6fS2LnbhYJ3wPpBCn9RmSOLPhBrsQx742aDQcGL1jxILamFcb8mxF1h
8IYaLv////8CUDR0AgAAAAAZdqkUkhXMoG2bpRdRBSEr8QmIRaCwX+OIrAAtMQEAAAAAF6kUlBbexafN
63o7rwuhT3h1Msx+kUKHAAAAAMlSQQQjIU9h69Jo0ZDbvlUfiRUXM68BPhPhW83eZf1zQhyQuoutpYlR
FUZ2rLYWEAo4hbL9smMPRzei8cDuvnkHgSkBQQTFlOfg3/UHkHyNIvk0TV4iJpzhs6CAMlRioRKWttLj
febe3hDfoDmoqaSZhmxcUHsNAtS06pVJ+AuKGjSMA5K6QQTOFdjRK/2+hr00V4iRFlzDXMS0Ll3fT+qJ
9YSH519IUTsIvhQenODRMReXXbfJmcCxUPg3N2TQvLX7iI2GRo2jU64IN210dmtDVGEA/////wNBBCMh
T2Hr0mjRkNu+VR+JFRczrwE+E+Fbzd5l/XNCHJC6i62liVEVRnasthYQCjiFsv2yYw9HN6LxwO6+eQeB
KQEAAEEExZTn4N/1B5B8jSL5NE1eIiac4bOggDJUYqESlrbS433m3t4Q36A5qKmkmYZsXFB7DQLUtOqV
SfgLiho0jAOSugAAQQTOFdjRK/2+hr00V4iRFlzDXMS0Ll3fT+qJ9YSH519IUTsIvhQenODRMReXXbfJ
mcCxUPg3N2TQvLX7iI2GRo2jAAACNAEAAAALEQkHGXapFCd8VsRZVBUqMoQpIAAPglG9VyAiiKxwb5gA
AAAAAAAABE5PTkUAAAAyAQAAAAsRCQcXqRSUFt7Fp83rejuvC6FPeHUyzH6RQoeAlpgAAAAAAAAABE5P
TkUAAAA=
================================================================================
```

### `ustx.multispend_partsign` — testMultisig.py:569-586

```
=====TXSIGCOLLECT-7oXWAFds======================================================
AQAAAAsRCQcAAAAAAf0bAwEAAAALEQkHSowkGdOEuZnpCexUrxsqIaabEZZYENZRdA/3sF/S7OgBAAAA
/QABAQAAAAE0v/Sl2nBWCT2EAqEpEUiCmAyCIEOsGcxHYIoqRAFW7gAAAACLSDBFAiBPTE3Xza0azFvA
RXvLgjd+AzM98GGvii+mz5MTaYA1JwIhAJ32cV134QHReN+b0W9ZFsYOuTWzAB321/2w4fYl0DSmAUEE
QbpfyJgN24LNDxkiRXdynkDwT6fS2LnbhYJ3wPpBCn9RmSOLPhBrsQx742aDQcGL1jxILamFcb8mxF1h
8IYaLv////8CUDR0AgAAAAAZdqkUkhXMoG2bpRdRBSEr8QmIRaCwX+OIrAAtMQEAAAAAF6kUlBbexafN
63o7rwuhT3h1Msx+kUKHAAAAAMlSQQQjIU9h69Jo0ZDbvlUfiRUXM68BPhPhW83eZf1zQhyQuoutpYlR
FUZ2rLYWEAo4hbL9smMPRzei8cDuvnkHgSkBQQTFlOfg3/UHkHyNIvk0TV4iJpzhs6CAMlRioRKWttLj
febe3hDfoDmoqaSZhmxcUHsNAtS06pVJ+AuKGjSMA5K6QQTOFdjRK/2+hr00V4iRFlzDXMS0Ll3fT+qJ
9YSH519IUTsIvhQenODRMReXXbfJmcCxUPg3N2TQvLX7iI2GRo2jU64IN210dmtDVGEA/////wNBBCMh
T2Hr0mjRkNu+VR+JFRczrwE+E+Fbzd5l/XNCHJC6i62liVEVRnasthYQCjiFsv2yYw9HN6LxwO6+eQeB
KQEAAEEExZTn4N/1B5B8jSL5NE1eIiac4bOggDJUYqESlrbS433m3t4Q36A5qKmkmYZsXFB7DQLUtOqV
SfgLiho0jAOSukcwRAIgK0UqQSZCBtaE6vQIQzd2cux7lCYz5F9WOsStmXuAy/4CIBogV6OLRM/W8Ia4
nc8m+JpnnQgVh+/LtO8OaNW4ev8+AQBBBM4V2NEr/b6GvTRXiJEWXMNcxLQuXd9P6on1hIfnX0hROwi+
FB6c4NExF5ddt8mZwLFQ+Dc3ZNC8tfuIjYZGjaMAAAI0AQAAAAsRCQcZdqkUJ3xWxFlUFSoyhCkgAA+C
Ub1XICKIrHBvmAAAAAAAAAAETk9ORQAAADIBAAAACxEJBxepFJQW3sWnzet6O68LoU94dTLMfpFCh4CW
mAAAAAAAAAAETk9ORQAAAA==
================================================================================
```

### `ustx.multispend_enoughsign` — testMultisig.py:590-608

```
=====TXSIGCOLLECT-7oXWAFds======================================================
AQAAAAsRCQcAAAAAAf1jAwEAAAALEQkHSowkGdOEuZnpCexUrxsqIaabEZZYENZRdA/3sF/S7OgBAAAA
/QABAQAAAAE0v/Sl2nBWCT2EAqEpEUiCmAyCIEOsGcxHYIoqRAFW7gAAAACLSDBFAiBPTE3Xza0azFvA
RXvLgjd+AzM98GGvii+mz5MTaYA1JwIhAJ32cV134QHReN+b0W9ZFsYOuTWzAB321/2w4fYl0DSmAUEE
QbpfyJgN24LNDxkiRXdynkDwT6fS2LnbhYJ3wPpBCn9RmSOLPhBrsQx742aDQcGL1jxILamFcb8mxF1h
8IYaLv////8CUDR0AgAAAAAZdqkUkhXMoG2bpRdRBSEr8QmIRaCwX+OIrAAtMQEAAAAAF6kUlBbexafN
63o7rwuhT3h1Msx+kUKHAAAAAMlSQQQjIU9h69Jo0ZDbvlUfiRUXM68BPhPhW83eZf1zQhyQuoutpYlR
FUZ2rLYWEAo4hbL9smMPRzei8cDuvnkHgSkBQQTFlOfg3/UHkHyNIvk0TV4iJpzhs6CAMlRioRKWttLj
febe3hDfoDmoqaSZhmxcUHsNAtS06pVJ+AuKGjSMA5K6QQTOFdjRK/2+hr00V4iRFlzDXMS0Ll3fT+qJ
9YSH519IUTsIvhQenODRMReXXbfJmcCxUPg3N2TQvLX7iI2GRo2jU64IN210dmtDVGEA/////wNBBCMh
T2Hr0mjRkNu+VR+JFRczrwE+E+Fbzd5l/XNCHJC6i62liVEVRnasthYQCjiFsv2yYw9HN6LxwO6+eQeB
KQEAAEEExZTn4N/1B5B8jSL5NE1eIiac4bOggDJUYqESlrbS433m3t4Q36A5qKmkmYZsXFB7DQLUtOqV
SfgLiho0jAOSukcwRAIgK0UqQSZCBtaE6vQIQzd2cux7lCYz5F9WOsStmXuAy/4CIBogV6OLRM/W8Ia4
nc8m+JpnnQgVh+/LtO8OaNW4ev8+AQBBBM4V2NEr/b6GvTRXiJEWXMNcxLQuXd9P6on1hIfnX0hROwi+
FB6c4NExF5ddt8mZwLFQ+Dc3ZNC8tfuIjYZGjaNIMEUCIQC5OkpGv/UnK/ih2GiUf9zHhBeJjYJG7YVM
ZvaRfXiZTgIgPsSob1XTyyX6i4HrKut4N+BjCQIoFT2xjFxwzXPcxGgBAAI0AQAAAAsRCQcZdqkUJ3xW
xFlUFSoyhCkgAA+CUb1XICKIrHBvmAAAAAAAAAAETk9ORQAAADIBAAAACxEJBxepFJQW3sWnzet6O68L
oU94dTLMfpFCh4CWmAAAAAAAAAAETk9ORQAAAA==
================================================================================
```

### `ustx.multispend_oversign` — testMultisig.py:612-631

```
=====TXSIGCOLLECT-7oXWAFds======================================================
AQAAAAsRCQcAAAAAAf2rAwEAAAALEQkHSowkGdOEuZnpCexUrxsqIaabEZZYENZRdA/3sF/S7OgBAAAA
/QABAQAAAAE0v/Sl2nBWCT2EAqEpEUiCmAyCIEOsGcxHYIoqRAFW7gAAAACLSDBFAiBPTE3Xza0azFvA
RXvLgjd+AzM98GGvii+mz5MTaYA1JwIhAJ32cV134QHReN+b0W9ZFsYOuTWzAB321/2w4fYl0DSmAUEE
QbpfyJgN24LNDxkiRXdynkDwT6fS2LnbhYJ3wPpBCn9RmSOLPhBrsQx742aDQcGL1jxILamFcb8mxF1h
8IYaLv////8CUDR0AgAAAAAZdqkUkhXMoG2bpRdRBSEr8QmIRaCwX+OIrAAtMQEAAAAAF6kUlBbexafN
63o7rwuhT3h1Msx+kUKHAAAAAMlSQQQjIU9h69Jo0ZDbvlUfiRUXM68BPhPhW83eZf1zQhyQuoutpYlR
FUZ2rLYWEAo4hbL9smMPRzei8cDuvnkHgSkBQQTFlOfg3/UHkHyNIvk0TV4iJpzhs6CAMlRioRKWttLj
febe3hDfoDmoqaSZhmxcUHsNAtS06pVJ+AuKGjSMA5K6QQTOFdjRK/2+hr00V4iRFlzDXMS0Ll3fT+qJ
9YSH519IUTsIvhQenODRMReXXbfJmcCxUPg3N2TQvLX7iI2GRo2jU64IN210dmtDVGEA/////wNBBCMh
T2Hr0mjRkNu+VR+JFRczrwE+E+Fbzd5l/XNCHJC6i62liVEVRnasthYQCjiFsv2yYw9HN6LxwO6+eQeB
KQFIMEUCIEp1ufpfgI5z1XwcZ9i8B7x7XwJ3mkUyCq56bOcuPTmqAiEA4V68y5iExV7VZbPqcdIxWS/w
WA8PpFqbkdqw/kJQNb4BAEEExZTn4N/1B5B8jSL5NE1eIiac4bOggDJUYqESlrbS433m3t4Q36A5qKmk
mYZsXFB7DQLUtOqVSfgLiho0jAOSukcwRAIgK0UqQSZCBtaE6vQIQzd2cux7lCYz5F9WOsStmXuAy/4C
IBogV6OLRM/W8Ia4nc8m+JpnnQgVh+/LtO8OaNW4ev8+AQBBBM4V2NEr/b6GvTRXiJEWXMNcxLQuXd9P
6on1hIfnX0hROwi+FB6c4NExF5ddt8mZwLFQ+Dc3ZNC8tfuIjYZGjaNIMEUCIQC5OkpGv/UnK/ih2GiU
f9zHhBeJjYJG7YVMZvaRfXiZTgIgPsSob1XTyyX6i4HrKut4N+BjCQIoFT2xjFxwzXPcxGgBAAI0AQAA
AAsRCQcZdqkUJ3xWxFlUFSoyhCkgAA+CUb1XICKIrHBvmAAAAAAAAAAETk9ORQAAADIBAAAACxEJBxep
FJQW3sWnzet6O68LoU94dTLMfpFCh4CWmAAAAAAAAAAETk9ORQAAAA==
================================================================================
```

### `ustx.ss2ms_unsigned` — testMultisig.py:635-645

```
=====TXSIGCOLLECT-HJqTvsXR======================================================
AQAAAAsRCQcAAAAAAf17AQEAAAALEQkH0yTdj/1epai7+ozi6P+QAGb7SC7heN8KKd7MXaylqCEBAAAA
/QABAQAAAAFzi65SWdroLD8dGjAFjvQhDnaRFW1HDwU0AiSXxKxPuQEAAACLSDBFAiEAkbFWoFx5lKs+
Q0OY3TL3lo1ckIeiZOPWB0giLsMvrP0CICJ26+e5IB8l20Luaj2+zxWCu7bxYpyFqB8AaPXBaB7/AUEE
IyFPYevSaNGQ275VH4kVFzOvAT4T4VvN3mX9c0IckLqLraWJURVGdqy2FhAKOIWy/bJjD0c3ovHA7r55
B4EpAf////8CQEtMAAAAAAAXqRTlgY0MJP3lDak826GfCJM965UHXIcwJEwAAAAAABl2qRRdhR54M5b6
KlxBD4fX4V7mP5EOKoisAAAAAAAAAP////8BQQT8+7E+Bne+Y73xPhAyqyWhlR4GNkYQsKcZvrWzNd/u
IHyxhCAOyWMdec+GFKDLijYgqVTXkF41k6cJCQtRMbvhAAACMgEAAAALEQkHF6kUlBbexafN63o7rwuh
T3h1Msx+kUKHAAk9AAAAAAAAAAROT05FAAAANAEAAAALEQkHGXapFLJqoSyMxawfCdRd3e5nFzk56v3l
iKwg9A4AAAAAAAAABE5PTkUAAAA=
================================================================================
```

### `ustx.ss2ms_signed` — testMultisig.py:649-660

```
=====TXSIGCOLLECT-HJqTvsXR======================================================
AQAAAAsRCQcAAAAAAf3CAQEAAAALEQkH0yTdj/1epai7+ozi6P+QAGb7SC7heN8KKd7MXaylqCEBAAAA
/QABAQAAAAFzi65SWdroLD8dGjAFjvQhDnaRFW1HDwU0AiSXxKxPuQEAAACLSDBFAiEAkbFWoFx5lKs+
Q0OY3TL3lo1ckIeiZOPWB0giLsMvrP0CICJ26+e5IB8l20Luaj2+zxWCu7bxYpyFqB8AaPXBaB7/AUEE
IyFPYevSaNGQ275VH4kVFzOvAT4T4VvN3mX9c0IckLqLraWJURVGdqy2FhAKOIWy/bJjD0c3ovHA7r55
B4EpAf////8CQEtMAAAAAAAXqRTlgY0MJP3lDak826GfCJM965UHXIcwJEwAAAAAABl2qRRdhR54M5b6
KlxBD4fX4V7mP5EOKoisAAAAAAAAAP////8BQQT8+7E+Bne+Y73xPhAyqyWhlR4GNkYQsKcZvrWzNd/u
IHyxhCAOyWMdec+GFKDLijYgqVTXkF41k6cJCQtRMbvhRzBEAiARp54CUAAnSuKOwadJpeh1krlJyEGX
ZqTV9KP4J8/1VwIgCI8MOAE4lIynyJ7aOSkIJ7KUjMn6aMCJTolck+gwXX8BAAIyAQAAAAsRCQcXqRSU
Ft7Fp83rejuvC6FPeHUyzH6RQocACT0AAAAAAAAABE5PTkUAAAA0AQAAAAsRCQcZdqkUsmqhLIzFrB8J
1F3d7mcXOTnq/eWIrCD0DgAAAAAAAAAETk9ORQAAAA==
================================================================================
```
