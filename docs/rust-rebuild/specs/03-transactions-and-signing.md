# 03 — Transactions, offline-signing interchange, coin selection, fees, message signing

Status: derived from source at HEAD (Armory 0.93.3, `BTCARMORY_VERSION = (0, 93, 3, 0)`,
ArmoryUtils.py:69). Python 2 was **not** executed. Every binary layout, ID formula,
sighash and signature check below was re-implemented in Python 3
(scratch decoder `ustx_decode.py`, not committed) and checked against the tiab golden
fixtures and the hard-coded vectors in `pytest/`. All IDs recompute exactly and all
stored signatures verify (§8).

Abbreviations used in citations:

| Abbrev | File |
|---|---|
| TX | `armoryengine/Transaction.py` |
| AU | `armoryengine/ArmoryUtils.py` |
| AS | `armoryengine/AsciiSerialize.py` |
| BP / BU | `armoryengine/BinaryPacker.py` / `armoryengine/BinaryUnpacker.py` |
| SC | `armoryengine/Script.py` |
| CS | `armoryengine/CoinSelection.py` |
| JV | `jasvet.py` |
| TF | `ui/TxFrames.py` |
| TD | `ui/toolsDialogs.py` |
| QD | `qtdialogs.py` |
| AQ | `ArmoryQt.py` |
| WLT | `armoryengine/PyBtcWallet.py` |
| BTU | `cppForSwig/BtcUtils.h` |
| EU | `cppForSwig/EncryptionUtils.cpp` |
| DS | `cppForSwig/cryptopp/DetSign.{h,cpp}` |

Related spec: `04-lockboxes-multisig.md` covers lockboxes, promissory notes and the
simulfunding workflow that also produces `TXSIGCOLLECT` blocks. This document owns the
USTX/USTXI/DTXO containers, signing and finalization.

---

## 0. Primitives

| Item | Definition | Source |
|---|---|---|
| Integers | `UINT8/16/32/64` little-endian unless stated | BP:42-60, BU:44-100 |
| `VAR_INT` | CompactSize: `n<0xfd` → 1 byte; `<2^16` → `fd`+u16; `<2^32` → `fe`+u32; else `ff`+u64 | AU:2284-2289 |
| `VAR_STR` | `VAR_INT(len) ‖ bytes` | BP:71-73 |
| `VAR_STR` read | **no bounds check on the payload**: a short buffer silently returns a truncated string (only 1 byte is size-checked) | BU:107-112 |
| `hash256` | SHA256(SHA256(x)); tx hashes are stored/serialized in internal (little-endian) order and displayed reversed (BE) | AU:1815 |
| `hash160` | RIPEMD160(SHA256(x)) | AU |
| `binary_to_base58` | big-endian integer → base58 (Bitcoin alphabet), one `'1'` per leading `0x00`, **no checksum** | AU:1997-2021 |
| `MAGIC_BYTES` | mainnet `f9 be b4 d9`, testnet `0b 11 09 07` | AU:474, AU:491 |
| `ADDRBYTE / P2SHBYTE` | mainnet `00`/`05`, testnet `6f`/`c4` | AU:479-480, AU:496-497 |
| scrAddr prefixes | network-independent: `00` P2PKH, `05` P2SH, `fe` multisig, `ff` non-std | AU:507-510, BTU:112-115 |
| `ONE_BTC` | 100 000 000 | AU:142 |
| `CENT` | 1 000 000 | AU:144 |
| `MIN_TX_FEE`, `MIN_RELAY_TX_FEE` | both 10 000 satoshi | AU:147-148 |
| `UINT32_MAX` | 2^32−1 (default `nSequence`) | AU:152 |
| `SECP256K1_ORDER` | `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` | AU:2439 |
| `MAX_COMMENT_LENGTH` | 144 (send-dialog comment field) | AU:177 |
| `DONATION` | 5 000 000 sat (0.05 BTC default donation row) | AU:143 |

`int_to_binary(i, widthBytes=0)` emits the *minimal* number of bytes (LE by default) and
**never truncates** when the value is wider than `widthBytes` (AU:1897-1915, AU:1956-1962).
This matters for `scriptPushData` (§7.4).

### 0.1 Raw transaction (`PyTx`, `PyTxIn`, `PyTxOut`, `PyOutPoint`)

Plain legacy Bitcoin serialization (no segwit marker/flag):

```
PyTx      := u32 version ‖ VAR_INT nIn ‖ PyTxIn* ‖ VAR_INT nOut ‖ PyTxOut* ‖ u32 lockTime     (TX:659-669)
PyTxIn    := PyOutPoint ‖ VAR_INT len ‖ script ‖ u32 sequence                                  (TX:533-539)
PyOutPoint:= 32-byte txHash (internal order) ‖ u32 txOutIndex                                  (TX:494-498)
PyTxOut   := u64 value ‖ VAR_INT len ‖ script                                                  (TX:597-602)
```

* Defaults: `PyTxIn.intSeq = 2**32-1` (TX:514), `PyTx.lockTime = 0` (TX:656).
* `PyTx.unserialize` does **not** reject trailing bytes; it records `nBytes` and
  `thisHash = hash256(serialize())` (TX:671-691). `PyOutPoint.unserialize` requires ≥36
  bytes (TX:489); `PyTxIn` checks `remaining ≥ scriptLen+4` (TX:524); `PyTxOut` checks
  `remaining ≥ scriptLen` (TX:585).
* `getHash()` = `hash256(serialize())`; `getHashHex()` defaults to **LE** hex (TX:693-697);
  GUI/RPC display uses BE.
* A segwit-serialized tx (marker `00 01`) would be misparsed as "0 inputs" — there is
  no segwit awareness anywhere (§10).

---

## 1. Offline-signing interchange: USTX ("TXSIGCOLLECT")

Three nested containers, all `AsciiSerializable` (AS:11):

* **UnsignedTransaction (USTX)** — TX:1917-2600
* **UnsignedTxInput (USTXI)** — TX:898-1605 (one per input; carries the *full* previous tx)
* **DecoratedTxOut (DTXO)** — TX:1625-1910 (one per output)

The same container is used for single-wallet offline signing (`*.unsigned.tx` →
`*.signed.tx`) and for multi-party signature collection (`*.sigcollect.tx`). There is
only one format; "signed" just means the per-key signature slots are filled.

Since 0.92 this format replaced the old BIP-0010 "TxDP" format; AQ:1666-1678 warns the
user that it is "not compatible with versions of Armory before 0.92".

### 1.1 USTX binary layout (`UnsignedTransaction.serialize`, TX:2179-2203)

| # | Field | Encoding | Notes |
|---|---|---|---|
| 1 | `version` | u32 | `UNSIGNED_TX_VERSION = 1` (TX:19) |
| 2 | `magic` | 4 bytes | `MAGIC_BYTES` of the network |
| 3 | `lockTime` | u32 | written from `self.lockTime` — see quirk Q1, always 0 in practice |
| 4 | `nIn` | VAR_INT | |
| 5 | `ustxi[i]` | VAR_STR | each = serialized USTXI (§1.2) |
| 6 | `nOut` | VAR_INT | |
| 7 | `dtxo[j]` | VAR_STR | each = serialized DTXO (§1.3) |

Unserialize (TX:2206-2242): read all fields; each USTXI/DTXO is unserialized with the same
`skipMagicCheck`; version mismatch → **warning only**; magic mismatch →
`NetworkIDError` unless `skipMagicCheck`; then `createFromUnsignedTxIO(ustxiList,
dtxoList, lockt)` rebuilds the tx; finally if an `expectID` was supplied (ASCII path) and
`expectID != uniqueIDB58` → `UnserializeError('ID on ascii block does not match computed
ID')` (TX:2236-2240). There is no check that the buffer was fully consumed.

### 1.2 USTXI binary layout (`UnsignedTxInput.serialize`, TX:1428-1453)

| # | Field | Encoding | Notes |
|---|---|---|---|
| 1 | `version` | u32 | 1 |
| 2 | `magic` | 4 bytes | |
| 3 | `outpoint` | 36 bytes | `txHash(32, internal order) ‖ u32 index` |
| 4 | `supportTx` | VAR_STR | **entire raw previous transaction** (source of value + scriptPubKey) |
| 5 | `p2shScript` | VAR_STR | redeem script if the prevout is P2SH, else empty |
| 6 | `contribID` | VAR_STR | free ASCII; lockbox ID / promissory-note ID, else empty |
| 7 | `contribLabel` | VAR_STR | UTF-8 (`toBytes`) on write, `toUnicode` on read |
| 8 | `sequence` | u32 | normally `0xffffffff` |
| 9 | `keysListed` (N) | VAR_INT | 1 for single-sig, N for M-of-N |
| 10 | N × `{pubKey, signature, wltLocator}` | 3 × VAR_STR each | signature = DER ‖ 1-byte hashtype, or empty; wltLocator normally empty |

Unserialize (TX:1456-1507):

1. Read fields as above. Build `pubMap[0x00 ‖ hash160(pub)] = pub` for every listed
   key, and `sigList = [[i, sig_i]]`, `locList = [[i, loc_i]]`.
2. `outpoint[:32] != hash256(supportTx)` → `UnserializeError` (TX:1483-1484).
3. `sequence != UINT32_MAX` → warning only. Magic mismatch → `NetworkIDError`
   (unless skip). Version mismatch → warning only.
4. Call the constructor `__init__(supportTx, outIdx = u32le(outpoint[-4:]), p2sh, pubMap,
   sigList, locList, contribID, contribLabel, seq, version)` which **re-derives**
   everything from `supportTx` (TX:957-1091):
   * `txoScript = supportTx.outputs[idx].script`, `value = …value`,
     `scriptType = getTxOutScriptType(txoScript)`.
   * If `scriptType == P2SH`: require `0x05 ‖ hash160(p2shScript) == scrAddr(txoScript)`
     else `InvalidScriptError`; then `scriptType = getTxOutScriptType(p2shScript)` and
     the *redeem script* becomes the base script (TX:1017-1037). (The `p2shScript is
     None` guard at TX:1020 is dead — the field is `''` when absent; a missing redeem
     script fails the hash check instead.)
   * Resulting `scriptType == P2SH` again → `InvalidScriptError('Cannot have recursive
     P2SH scripts!')` (TX:1042-1046).
   * Single-sig (`STDHASH160`, `STDPUBKEY65`, `STDPUBKEY33`): `scrAddr =
     script_to_scrAddr(baseScript)` (always prefix `00` + hash160 of the key — also for
     P2PK, BTU:999-1036); `pubKeyMap[scrAddr]` must exist else
     `KeyDataError('Must give pubkey map for singlesig USTXI!')`; M = N = 1.
   * Multisig: `M, N, a160s, pubs = getMultisigScriptInfo(baseScript)`; **pubKeys come from
     the script itself**, not from the serialized key list (the serialized pubkeys are
     ignored for multisig). `scrAddrs = [0x00 ‖ a160]`.
   * Anything else: `LOGWARN("Non-standard script for TxIn %d" % i)` — `i` is undefined
     there, so this raises `NameError` (TX:1065-1067). Non-standard prevouts cannot be
     put in a USTX.
   * Signatures/locators are re-inserted by index; `index >= keysListed` → logged and
     skipped (TX:1083-1088).

`wltLocator` is documented as a 4-byte BIP32-ish hint for keyless HW wallets; nothing in
0.93.3 writes a non-empty one (TX:912-919, 1110-1121).

### 1.3 DTXO binary layout (`DecoratedTxOut.serialize`, TX:1794-1813)

| # | Field | Encoding | Notes |
|---|---|---|---|
| 1 | `version` | u32 | 1 |
| 2 | `magic` | 4 bytes | |
| 3 | `binScript` | VAR_STR | the scriptPubKey actually placed in the tx |
| 4 | `value` | u64 | satoshis |
| 5 | `p2shScript` | VAR_STR | optional redeem script for a P2SH destination (display only) |
| 6 | `wltLocator` | VAR_STR | empty |
| 7 | `authMethod` | VAR_STR | always the ASCII string `NONE` in practice |
| 8 | `authData` | VAR_STR | `NullAuthData.serialize()` = empty (TX:1608-1622) |
| 9 | `contribID` | VAR_STR | |
| 10 | `contribLabel` | VAR_STR | written raw (no `toBytes`), read with `toUnicode` |

Unserialize (TX:1816-1847): magic → `NetworkIDError`; version → warning; `authData` is
discarded and replaced by `NullAuthData`. Derived: `scrAddr`, `scriptType`, and for
multisig (bare, or P2SH with redeem script supplied) `multiInfo = {M, N, Addr160s,
PubKeys}` (TX:1665-1682).

### 1.4 Rebuilding the unsigned tx and the USTX ID (`createFromUnsignedTxIO`, TX:1969-2015)

```
tx.version  = UNSIGNED_TX_VERSION (=1)              # TX:1978 — container version reused as Bitcoin tx version
tx.lockTime = lockTime argument
tx.inputs[i]  = (ustxi[i].outpoint, script = '', sequence = ustxi[i].sequence)
tx.outputs[j] = (dtxo[j].value, dtxo[j].binScript)
fee = Σ ustxi.value − Σ dtxo.value
  fee > 100*MIN_RELAY_TX_FEE (0.01 BTC) → warning only (TX:2003-2008)
  fee < 0 → ValueError                                 (TX:2009-2010)
uniqueIDB58 = binary_to_base58(hash256(tx.serialize()))[:8]   (TX:2011-2013)
asciiID     = uniqueIDB58
```

* Inputs and outputs keep the list order of the USTXI/DTXO lists. Input order is
  re-checked at finalization (`verifyInputsMatchPyTxObj`, TX:2381-2396).
* Because input scripts are empty, the ID is stable across signing (unsigned and
  signed files have the same ID).
* The ID is the first 8 base58 characters of the 32-byte hash taken as a big-endian
  integer **in internal byte order** (not the reversed txid). Verified: §8, §9.3.

### 1.5 ASCII armor (`makeAsciiBlock` / `readAsciiBlock`, AU:1326-1356; AS:65-79)

Writer (`serializeAscii`, AS:65-68 → AU:1326-1335):

```
line 0 : ("=====" + "TXSIGCOLLECT" + "-" + ID).ljust(W, "=")
lines  : base64(standard alphabet, with '=' padding) of the USTX bytes, W chars per line (last line shorter)
last   : "=" * W
joined : "\n"  (no trailing newline)
```

* **W = 64** is the current default (`makeAsciiBlock(..., wid=64)`, AU:1326).
* **All golden fixtures and all test blocks use W = 80** (fixture header and footer lines
  are exactly 80 chars; base64 lines 80 chars) and the fixture files use **CRLF** line
  endings. Readers must accept any width and any line ending.
* `EMAILSUBJ = 'Armory Multi-sig Transaction to Sign - %s'` (TX:1935) and an
  `EMAILBODY` (TX:1936-1945) are used by the lockbox "email" export.

Reader (`unserializeAscii`, AS:71-79 → AU:1338-1356):

1. `lines = block.strip().split()` — splits on **any whitespace**, so width and CR/LF
   are irrelevant.
2. Require `lines[0].startswith('=====')` and `lines[-1].startswith('======')`, else
   return `(lines[0].strip('='), None)` → `UnserializeError('Unexpected BLKSTRING')`.
   Note `readAsciiBlock` overwrites its `headStr` parameter with `''` on entry
   (AU:1339), so the **block type (`TXSIGCOLLECT`) is not actually checked**; any
   `=====XXXX-ID====` header is accepted and parsed as a USTX.
3. `headStr = lines[0].strip('=')`; `raw = base64decode(''.join(lines[1:-1]))`.
4. `expectID = headStr.split('-')[-1]`; `unserialize(raw, expectID, skipMagicCheck)` —
   the ID **is** enforced (TX:2236-2240).

### 1.6 Signature attachment and finalization

* `insertSignatureForInput(i, sig, pubKey=None)` (TX:2465-2472): validates the sig against
  the rebuilt unsigned tx (§3) and stores it in the slot of the pubkey it verifies
  against; returns the slot index or −1.
* `insertSignature(sig, pubKey)` (TX:2475-2485) and `USTXI.insertSignature`
  (TX:1227-1245): **no verification**; puts the sig in every slot whose pubkey equals
  `pubKey` (handles repeated keys in a multisig).
* `createAndInsertSignatureForInput(i, privKey)` (TX:2455-2462 → TX:1248-1253): sign (§3)
  and insert by computed pubkey.
* Wallet signing `PyBtcWallet.signUnsignedTx(ustx, hashcode=1)` (WLT:2703-2760): for each
  USTXI, for each `scrAddr` slot, if the wallet has that hash160 *and* the private key,
  sign that input. Rejects `hashcode != 1`. Requires unlocked wallet. Advances the
  wallet's highest-used chain index to the max index used.

Signing status (`evaluateSigningStatus`, TX:1510-1547 per input, TX:2328-2370 per tx):

`TXIN_SIGSTAT` enum (TX:789-792) — integer order matters because statuses are `sorted()`:

| value | name | display char |
|---|---|---|
| 0 | `ALREADY_SIGNED` | `#` |
| 1 | `WLT_ALREADY_SIGNED` | `@` |
| 2 | `WLT_CAN_SIGN` | `-` |
| 3 | `NO_SIGNATURE` | `_` |

Per input: `statusN[k] = ALREADY_SIGNED` if slot k has a (non-empty) sig; if a wallet is
given and owns `scrAddrs[k]`: `WLT_ALREADY_SIGNED` / `WLT_CAN_SIGN`. `statusM =
sorted(statusN)[:M]`; `allSigned = statusM[-1] in {0,1}`; `wltCanComplete = statusM[-1]
== 2`. **This only checks presence of bytes, not validity.** Per tx: `canBroadcast` = all
inputs `allSigned`. `TX_SIGSTAT` enum (TX:795-798) is defined but unused by this logic.

Finalization (`getSignedPyTx(doVerifySigs=True, stripExtraSigs=True)`, TX:2404-2431):

1. Inputs must be in the same order as `pytxObj` (else `None`).
2. If `doVerifySigs`: every input must pass `verifyAllSignatures` (≥ M slots that are
   present **and** cryptographically valid, TX:1318-1340) else `SignatureError`.
3. For each input `createSigScript(stripExtraSigs)` (TX:1124-1191):
   * single-sig with empty sig → returns `''` → `getSignedPyTx` returns `None`.
   * **Low-S + DER re-normalization of every stored sig** (`getRSFromDERSig` →
     `createDERSigFromRS` + original hashtype byte), and the normalized sig is written
     back into `self.signatures` (TX:1148-1160). Stored sigs in a USTX may therefore be
     high-S (fixture `8gRmZv48` is), the broadcast tx never is.
   * `STDPUBKEY33/65` (P2PK): `push(sig)`.
   * `STDHASH160` (P2PKH): `push(sig) ‖ push(pubKey)`.
   * `MULTISIG`: `OP_0 ‖ push(sig_k)…` over slots in **pubkey order**, empty slots
     skipped. With `stripExtraSigs`, while the number of present sigs > M, `pop()` the
     **last list element** (TX:1172-1175) — i.e. extra signatures are dropped from the
     highest slot indices.
   * If `p2shScript` non-empty: append `push(p2shScript)`.
   * `push` = `scriptPushData` (§7.4).
4. `getBroadcastTxIfReady` (TX:2488-2496) returns `None` on `SignatureError`.

The GUI writes the signed USTX back as ASCII (`*.signed.tx`) and the online machine calls
`getSignedPyTx()` → raw tx → broadcast (TF:1742-1803, `armoryd sendasciitransaction`
armoryd.py:291-322). `TF.copyTxHex` gives the raw hex (TF:1878-1883).

### 1.7 USTX construction paths

| Function | Purpose | Notes |
|---|---|---|
| `createFromTxOutSelection(utxos, scriptValuePairs, pubKeyMap, txMap, p2shMap)` TX:2099-2149 | GUI/armoryd send | builds a `PyTx` with version 1, lockTime 0, seq `0xffffffff`, then `createFromPyTx`. Non-standard output scripts → warning only. Requires Σutxo ≥ Σoutputs. |
| `createFromPyTx(pytx, pubKeyMap, txMap, p2shMap)` TX:2018-2093 | | each input's supporting tx from `txMap[txHash]` or the BDM (`getTxByHash`); otherwise `BlockchainUnavailableError`/`InvalidHashError`. P2SH prevout → `p2shMap[hex(scrAddr)]` required. |
| `createFromUnsignedTxInputSelection(ustxiList, svPairs, p2shMap, lockTime)` TX:2152-2162 | promissory/simulfund | |
| `createFromUnsignedTxIO(ustxiList, dtxoList, lockTime)` TX:1969-2015 | all paths end here | |
| `PyCreateAndSignTx(ustxiList, dtxoList, privKeyMap)` TX:2604-2621 | sweeping imported keys | signs every slot from `{scrAddr: privKey}`; raises if any missing |
| `PyCreateAndSignTx_old` TX:2649-2757 | test helper (coinbase/reorg tests) | hand-rolled sigScripts; no low-S |

`p2shMap` key mismatch (quirk Q4): inputs look up `p2shMap.get(binary_to_hex(scrAddr))`
(TX:2071) but outputs look up `p2shMap.get(scrAddr)` with the raw bytes (TX:2088, 2159).
TF/armoryd build the map with hex keys (TF:738-739, armoryd.py:1980-1981), so DTXO
`p2shScript` is never populated by those paths.

### 1.8 JSON map form (`toJSONMap` / `fromJSONMap`)

Used only inside promissory notes (MultiSigUtils.py:1021-1063); never written to files by
itself. Keys:

* USTXI (TX:1343-1376): `version, magicbytes(hex), outpoint(hex 36B), p2shscript(hex),
  contribid, contriblabel, sequence, numkeys, keys[{pubkeyhex, dersighex, wltlochex}],
  supporttxhash_le, supporttxhash_be, supporttxhash (=BE), supporttxoutindex,
  inputvalue`, and `supporttx` (hex) unless `lite`. `fromJSONMap` requires `supporttx`.
* DTXO (TX:1694-1756): `version, magicbytes, txoutscript, txoutvalue, p2shscript,
  wltlocator, authmethod, authdata, contribid, contriblabel, scripttypeint,
  scripttypestr, isp2sh, ismultisig, hasaddrstr, addrstr`.
* USTX (TX:2246-2287): `version, magicbytes, id, locktimeint, locktimeblock (-1 if ≥
  500000000), locktimedate, numinputs, numoutputs, suminputs, sumoutputs, fee,
  inputs[], outputs[]`.

### 1.9 Layout generations observed in the wild (all claim `version = 1`)

| Gen | USTXI fields 6-7 | DTXO fields 9-10 | Where seen | Parsed by 0.93.3? |
|---|---|---|---|---|
| G0 | `contribID` only (no `contribLabel`) | **neither** `contribID` nor `contribLabel` | `pytest/testMultisig.py:269-305` (`asc_nosig`, `asc_sig`, ID `5JxmLy4T`) — the test that would parse them is commented out (testMultisig.py:324-325) | **No** |
| G1 | `contribID` only | `contribID` only | tiab fixtures `armory_Ev9L4wAd_.signed.tx`, `armory_EyUJNfMQ_.unsigned.tx` (May 7 2014) | **No** (fails with `UnpackerError`/garbage) |
| G2 | `contribID` + `contribLabel` | `contribID` + `contribLabel` | current writer; tiab `8gRmZv48`, `fmuHCs5G`; all `serMap['ustx']` blocks | Yes |

The `version` field does **not** discriminate. A Rust reader that wants to accept G0/G1
must try G2 first and fall back to the shorter layouts, validating by "buffer exactly
consumed + outpoint hash matches supportTx + recomputed ID == header ID" (this is how the
fixtures were decoded in §8). The ID formula is identical in all generations.

### 1.10 Legacy TxDP (BIP-0010) format

**Not parsed by 0.93.3.** `PyTxDistProposal` no longer exists anywhere in `armoryengine`
(grep: only referenced by `extras/cli_sign_txdp.py:29`, `extras/createTxFromAddrList.py:130`,
`extras/PromoKit.py:285` — dead scripts that would raise `NameError`). No
`-----BEGIN-TRANSACTION-` parser remains; git history in this clone does not contain it.
`extras/cli_sign_txdp.py` is therefore documentation of the *old CLI workflow only*
(reads wallet + `*.unsigned.tx`, prints inputs/outputs/fee, asks y/N, unlocks with up to
3 passphrase tries, signs, writes `<name>.signed.tx` by replacing the last two dot
components, offers to delete the unsigned file — cli_sign_txdp.py:12-108).

### 1.11 File naming conventions (GUI)

| Action | Default file name | Source |
|---|---|---|
| Save unsigned (send dialog) | `armory_<ID>_.unsigned.tx` (Windows: `armory_<ID>_` + filter suffix) | TF:1300-1316 |
| Save from review dialog | `armory_<ID>_.signed.tx` / `.unsigned.tx` | TF:1828-1856 |
| Auto-save after signing a loaded file | loaded name with `unsigned`→`signed`, old file deleted | TF:1805-1825 |
| After broadcast of a loaded file | file renamed `signed`→`SENT` | TF:1786-1797 |
| Load filter | `*.signed.tx *.unsigned.tx *.SENT.tx` | TF:1859-1868 |
| Lockbox spend | `MultisigTransaction_<ID>_.sigcollect.tx` | ui/MultiSigDialogs.py:3057 |
| Simulfunding | `Simulfund_<ID>.sigcollect.tx` | ui/MultiSigDialogs.py:3836 |

The file name is not authoritative: tiab `armory_EyUJNfMQ_.unsigned.tx` carries header
ID `Ev9L4wAd` (which is also its correct computed ID).

---

## 2. Signable input types and how prevout data is carried

| Prevout script (`getTxOutScriptType`) | USTXI `scriptType` | Keys | Sign (createTxSignature) | Verify | sigScript built |
|---|---|---|---|---|---|
| P2PKH, uncompressed key (`STDHASH160`) | 0 | 1 (from pubKeyMap) | **yes** | yes | `push(sig) push(pub65)` |
| P2PKH, compressed key | 0 | 1 | **no** — see below | **no** — see below | `push(sig) push(pub33)` (only if a sig is inserted unverified) |
| P2PK 65 (`STDPUBKEY65`) | 1 | 1 | yes | yes | `push(sig)` |
| P2PK 33 (`STDPUBKEY33`) | 2 | 1 | no | no | `push(sig)` |
| Bare multisig (`MULTISIG`), all keys uncompressed | 3 | N from script | yes (per slot) | yes | `OP_0 push(sig)…` |
| P2SH → multisig redeem (`P2SH` + p2shScript) | 3 (sub-type) | N from redeem script | yes | yes | `OP_0 push(sig)… push(redeem)` |
| P2SH → P2PKH / P2PK redeem | 0/1/2 (sub-type) | 1 | as above | as above | `… push(redeem)` |
| P2SH → P2SH | — | — | `InvalidScriptError` | | |
| Non-standard | — | — | cannot construct (NameError, TX:1066) | | |

Compressed keys:

* `createTxSignature` computes `CryptoECDSA().ComputePublicKey(priv)` — always the
  **65-byte uncompressed** key — and requires it to be `in self.pubKeys`
  (TX:1207-1210), so a slot holding a 33-byte key can never be signed.
* Verification calls `CryptoECDSA::VerifyData` → `ParsePublicKey(pubKey65B)`, which
  slices bytes 1..33 and 33..65 unconditionally (EU:453-458) — a 33-byte key is
  mis-parsed (and `Validate` is `assert`ed, EU:477). Compressed-key inputs therefore
  cannot be verified by the USTX code either.
* Armory 1.35 wallets only hold uncompressed keys (`PyBtcAddress.isCompressed()` returns
  `False`, PyBtcAddress.py:172-174); importing a compressed WIF raises
  `CompressedKeyError` (AU:2873-2874, QD:3130-3135); `privKey_to_base58` never appends the
  `01` flag (AU:2066-2071). Send paths fill `pubKeyMap` with `binPublicKey65`
  (TF:752-762, armoryd.py:1998-2005).
* `getMultisigScriptInfo` accepts 33- and 65-byte keys in multisig scripts
  (TX:322-361), so multisig scripts *containing* compressed keys can be represented, but
  those slots can't be signed/verified by Armory.

Prevout data: every USTXI embeds the full previous transaction (`supportTx`). Value and
scriptPubKey are always re-derived from it and the outpoint hash is checked against it
(TX:1483). This is how an offline signer learns input amounts (the fee shown to the
user is `Σ ustxi.value − Σ dtxo.value`, TX:2171-2175). There is no field for a bare
"amount" — unlike PSBT `witness_utxo`, the whole tx is mandatory.

Contributor metadata (`contribID`/`contribLabel`) groups inputs/outputs by funder in
the lockbox / simulfund UIs (TX:924-927, 1637-1641; see spec 04).

---

## 3. Sighash, signatures, nonces

### 3.1 Sighash preimage (`generatePreHashTxMsgToSign`, TX:857-895)

Only `SIGHASH_ALL (=1)` is accepted: any other `hashcode` → logs error and returns `None`
(TX:866-870). Algorithm for input `i`:

1. Copy the tx. Set **every** input script to empty.
2. Set input `i`'s script to `subscript` where `subscript = p2shScript if non-empty else
   txoScript` (`getTxoScriptToSign`, TX:1314-1315) — i.e. for P2SH the **redeem script**,
   otherwise the prevout scriptPubKey verbatim.
3. (Dead code for NONE/SINGLE/ANYONECANPAY, TX:877-886.)
4. `preimage = tx.serialize() ‖ u32le(hashcode)`; return `(preimage, byte(hashcode))`.

No `OP_CODESEPARATOR` stripping and no `FindAndDelete` of the signature are performed
(standard scripts don't need them). The ECDSA message digest is `z = hash256(preimage)`,
computed inside the C++ signer (§3.2). The signature-hash constants exist
(`SIGHASH_ALL=1, NONE=2, SINGLE=3, ANYONECANPAY=0x80`, TX:21-24) but are unusable.

Verification (`getValidIndexForSignature`, TX:1260-1311): locate the tx input by
outpoint; if no pubkey given, try every slot; parse DER with `getRSFromDERSig`; hashtype
= last byte; **`hashtype != 1` → −1**; verify `(r‖s)` against `preimage` with
`CryptoECDSA().VerifyData` (which SHA256s the preimage once and lets Crypto++ hash again,
EU:686-707). Crypto++ verification accepts both low-S and high-S signatures.

### 3.2 Signing (`createTxSignature`, TX:1194-1224; `CryptoECDSA::SignData`, EU:607-662)

```
require pub65(priv) ∈ ustxi.pubKeys                               # TX:1207-1210
i   = index of ustxi.outpoint in pytx.inputs                       # TX:1212-1218
msg = generatePreHashTxMsgToSign(pytx, i, subscript, 1)
sig = CryptoECDSA.SignData(msg, priv, DetSign=ENABLE_DETSIGN)      # 64 bytes r‖s (P1363)
return createDERSigFromRS(sig[:32], sig[32:]) ‖ 0x01
```

`SignData` computes `hashVal = SHA256(msg)` and passes it as the "message" to a Crypto++
`ECDSA<ECP,SHA256>` signer, which hashes once more → `e = SHA256(SHA256(msg)) = z`
(EU:634-646; Crypto++ `DL_SignatureMessageEncodingMethod_DSA`, cryptopp/gfpcrypt.cpp:69-89).

### 3.3 Nonce generation

* `ENABLE_DETSIGN` defaults to **True** (`--enable-detsign` / `--disable-detsign`,
  AU:121-124, AU:279).
* Deterministic path: `BTC_DETSIGNER = ECDSA_DetSign<ECP,SHA256>::DetSigner`
  (EncryptionUtils.h:125). `DL_SignerImplDetSign::SignAndRestart` computes the DSA
  representative `e = z` and then calls `getDetKVal(priv, representative=e, …)`
  (DS DetSign.h:62-85). `getDetKVal` implements RFC 6979 §3.2 with HMAC-SHA256,
  `V=0x01…`, `K=0x00…`, `int2octets(x)` 32 bytes, retry loop (DetSign.cpp:120-200) — **but
  it first hashes its input**: `h1 = SHA256(msgToHash)` (DetSign.cpp:139-142).
  Therefore Armory's nonce is

  `k = RFC6979_HMAC_SHA256(x, h1 = SHA256(z))`   where `z = hash256(preimage)`

  whereas Bitcoin Core / libsecp256k1 use `h1 = z`. Armory signatures are valid but will
  **not** byte-match a stock libsecp256k1 / `k256` RFC 6979 signer. The standalone
  `getDetKVal` matches the standard secp256k1 RFC 6979 vectors (§9.6, re-verified in
  Python 3), which confirms the HMAC-DRBG part; the extra SHA256 is the only deviation.
  A Rust port that needs byte-identical output must feed `SHA256(z)` as the RFC 6979
  message hash (e.g. RFC6979 with message = `z` and H = SHA256), or accept divergence.
* Non-deterministic path (`--disable-detsign`): `BTC_SIGNER` with
  `AutoSeededX917RNG<AES>` (EncryptionUtils.h:115-124).

### 3.4 DER encoding and low-S (`createDERSigFromRS` / `getRSFromDERSig`, AU:2971-3020)

`createDERSigFromRS(rBin, sBin)` (32-byte BE inputs):

1. Strip leading `0x00` from r and s.
2. If `s > n/2` (integer division of the order): `s = n − s` re-encoded minimally (BIP62
   low-S; added in commit `7dfb0ad`, Oct 2015).
3. If the high bit of the first byte is set, prepend `0x00` (r and s independently).
4. `30 ‖ len(r)+len(s)+4 ‖ 02 ‖ len(r) ‖ r ‖ 02 ‖ len(s) ‖ s` (all lengths single bytes).
   Edge: r or s = 0 would index an empty string (crash); unreachable in practice.

`getRSFromDERSig(der)`: asserts `0x30`, total length byte equals remaining length,
`0x02` tags; returns r, s each left-stripped of zeros and left-padded to 32 bytes.
**No strict-DER checks** (negative numbers, excess padding, trailing bytes after s are
tolerated as long as the outer length matches). Note a sig with the hashtype byte
appended passes because `nBytes` comes from `der[1]` and only `der[2:2+nBytes]` is read.

Low-S is applied (a) at signing time for new sigs (`createTxSignature` → DER), and (b)
again to **every** stored sig in `createSigScript` (§1.6). Message signatures (§5) are
**not** low-S normalized.

### 3.5 Python script evaluator (`PyScriptProcessor`, SC:128-688) — verification aid only

Not used for USTX finalization (TX:2412-2416 explicitly avoids it because "it doesn't
currently handle P2SH scripts properly"). Used by tests. Facts a port must not copy as
consensus:

* Executes scriptSig then scriptPubKey on a shared stack (SC:177-200); **no P2SH**
  evaluation; result `stack[-1] == 1`.
* `OP_IF/NOTIF/ELSE/ENDIF` → `OP_NOT_IMPLEMENTED` (SC:353-360).
* `OP_CAT, SUBSTR, LEFT, RIGHT, INVERT, AND, OR, XOR, 2MUL, 2DIV, MUL, DIV, MOD, LSHIFT,
  RSHIFT` → `OP_DISABLED`.
* Implemented: pushes (0, 1-75, PUSHDATA1/2/4), `1NEGATE`, `OP_1..16` (as Python ints),
  `NOP, VERIFY, RETURN, TOALTSTACK, FROMALTSTACK, IFDUP, DEPTH, DROP, DUP, NIP, OVER,
  PICK, ROLL, ROT, SWAP, TUCK, 2DROP, 2DUP, 3DUP, 2OVER, 2ROT, 2SWAP, SIZE, EQUAL,
  EQUALVERIFY, 1ADD, 1SUB, NEGATE, ABS, NOT, 0NOTEQUAL, ADD, SUB, BOOLAND, BOOLOR,
  NUMEQUAL(VERIFY), NUMNOTEQUAL, LESSTHAN, GREATERTHAN, (LESS|GREATER)THANOREQUAL, MIN,
  MAX, WITHIN, RIPEMD160, SHA1, SHA256, HASH160, HASH256, CODESEPARATOR, CHECKSIG(VERIFY),
  CHECKMULTISIG(VERIFY)`; anything else (incl. `NOP1-10`, CLTV/CSV) → `SCRIPT_ERROR`.
* Known defects: `OP_0` pushes int `0` not `''`; `castToBool` compares a str char to int
  `0x80` (SC:228-238); `checkSig` discards the result of the OP_CODESEPARATOR `replace`
  (SC:270); `*VERIFY` variants call `executeOpCode(OP_VERIFY)` with missing args
  (SC:617-619, 676-679) → `TypeError`; `OP_0NOTEQUAL` pops twice; `OP_2ROT` doesn't
  remove; non-1 hashtype → `assert(False)` (SC:263-265).

---

## 4. Coin selection and fees (`CoinSelection.py`, `TxFrames.py`, `armoryd.py`)

### 4.1 Inputs to selection

* GUI: `wlt.getUTXOListForSpendVal(totalSend)` → C++
  `BtcWallet::getSpendableTxOutListForValue(val, ignoreZC)` (BtcWallet.cpp:502-543): "grabs
  at least 100 UTXOs with enough spendable balance to cover 2x val (if available),
  otherwise the full list" (prefilter; order is per-scrAddr map order). Coin control
  replaces this with all spendable UTXOs of the chosen addresses (TF:853-873). Lockboxes
  use the lockbox's C++ wallet (TF:875-881).
* `PyUnspentTxOut` fields: `scrAddr, txHash, txOutIndex, val, conf (numConfirm), binScript`
  (CS:79-139). `conf` = confirmations at current top block (CS:89).
* `IGNOREZC` (CLI option `ignoreAllZC`, AU:273) excludes zero-conf UTXOs.

### 4.2 Sort orders (`PySortCoins`, CS:166-257)

All "reverse=True" sorts are descending; Python `sorted` is stable.

| m | key | notes |
|---|---|---|
| 0 | `val * conf` | |
| 1 | `(val * conf) ** (1/3.)` | same order as 0 |
| 2 | `(ln(val*conf + 1) + 4) ** 4` | same order as 0 |
| 3 | `val if conf > 0 else 0` | |
| 4 | group by address string (`script_to_addrStr` if `HAS_ADDRSTR` else scrAddr), zero-conf UTXOs removed and appended at the end; within a group sort by `conf * val**0.333` desc; groups ordered by their max of that key desc | dict iteration order (Py2 hash order) affects tie-breaks |
| 5,6,7 | sort 1, then rotate the first `m−4` elements to the end | |
| 8 | non-zero-conf UTXOs `random.shuffle`d, zero-conf appended | **nondeterministic** |
| 9 | sort 1, then `topsz = int(min(max(round(sz/3), 5), sz))` random swaps between index `uniform(0,topsz)` and `uniform(0, sz−topsz)` (sz = #non-zero-conf) | **nondeterministic**; Py2 integer `sz/3` |

### 4.3 Primitive selectors (CS:259-386)

`target = targetOutVal + minFee`.

* `SingleInput_SingleValue` (CS:259-305): smallest UTXO with `value ≥ target`. Intended
  second pass to avoid change < CENT is **dead** (typo `try2Val = utxo`, CS:295-296, so
  `try2Utxo` stays `None`). Returns `[best]` or `[]`.
* `MultiInput_SingleValue` (CS:308-327): accumulate in list order until `sum ≥ target`;
  returns the prefix (possibly insufficient — scored −1 later).
* `SingleInput_DoubleValue` (CS:331-363): `ideal = 2*targetOutVal + minFee`;
  `minT = max(long(0.75*ideal), targetOutVal+minFee)`; `maxT = long(1.25*ideal)`;
  if `Σall < minT` → `[]`; pick the single UTXO in `[minT, maxT]` minimizing
  `|v − ideal|` (first wins ties).
* `MultiInput_DoubleValue` (CS:366-386): `ideal = 2.0*targetOutVal` (float, **no fee**);
  `minT = max(long(0.80*ideal), targetOutVal+minFee)`; if `Σall < minT` → `[]`;
  accumulate; stop and drop the last element when `sum ≥ minT` and the distance to
  `ideal` started increasing.

### 4.4 Scoring (`getSelectCoinsScores`, CS:392-561; `PyEvalCoinSelect`, CS:584-614)

Given a selection, `totalIn`, `change = totalIn − (target+minFee)`:

* Empty or `totalIn < targetOutVal + minFee` → score −1.
* `noZeroConf` = 0 if any selected UTXO has `conf == 0`, else 1.
* `numAddrFactor = 4.0 / (numDistinctScrAddr + 1)**2`.
* Output anonymity: `countTrailingZeros(v)` = number of trailing decimal zeros of the
  satoshi value (loop i=1..19). `zeroDiff = tz(target) − tz(change)`. If `change == 0` →
  1; elif zeroDiff == 2 → 0.2; == 1 → 0.7; < 1 → `|zeroDiff| + 1`; (≥3 → 0). Then if
  `0 < f ≤ 1` and change ≠ 0: `diffPct = |change − target| / max(change, target)` using
  **Py2 integer division** (CS:479) — so `diffPct` is 0 unless the diff ≥ the max, i.e.
  this branch effectively always multiplies by 1 (or zeroes the factor when diffPct ≥ 1,
  which is impossible for positive values).
* Size estimate: `numBytes = 10 + 180*nIn + 35*(1 if change==0 else 2)`;
  `numKb = numBytes // 1000`.
* Priority: `dPriority = Σ(val*conf over conf>0) // numBytes` (integer division);
  `priorityThresh = ONE_BTC*144/250 = 57 600 000`; factor 0 / 0.7 (<10×) / 0.9 (<100×) / 1.0.
* `isFreeAllowed = (not dust) and dPriority ≥ thresh and numBytes ≤ 10000` where
  `dust = (0 < change < CENT) or targetOutVal < CENT`.
* `txSizeFactor`: 1 if free or `numKb < 1`; else 0.2 (<2 kB), 0.1 (<3), 0 (<4), −1.
* Returns `(isFreeAllowed, noZeroConf, priorityFactor, numAddrFactor, txSizeFactor,
  outAnonFactor)`.

Weights (CS:570-582): `ALLOWFREE 100000, NOZEROCONF 1000000, PRIORITY 50, NUMADDR 100000,
TXSIZE 100, OUTANONYM 30`. `score = Σ w*s` except the ALLOWFREE term is only added when
`minFee < 0.0005` (CS:610) — this compares **satoshis** to a float, so it applies only
when `minFee == 0`.

### 4.5 `PySelectCoins(utxos, targetOutVal, minFee=0, numRand=10, margin=CENT)` (CS:620-718)

1. If `Σutxos < targetOutVal` → `[]` (note: fee not included).
2. Candidates, in this order: for sort m in 0..7, the eight combos
   `{SingleInput_SingleValue, MultiInput_SingleValue, SingleInput_DoubleValue,
   MultiInput_DoubleValue} × {targExact = targetOutVal, targMargin = targetOutVal+CENT}`
   (exact order at CS:636-645); then for method 8,9 × `numRand` (10) iterations, four
   multi-input candidates each (CS:652-658). Total 64 + 80 = 144 candidates.
3. `final = max(candidates, key=score)` — Python `max` returns the **first** maximal
   element in list order.
4. Sweep-in of dust (CS:685-717): if `len(final) < 5` and `outAnonFactor == 0`: walk all
   UTXOs sorted by `val*conf` ascending; add those not already selected, from an address
   already used, `conf > 0`, and `val*conf ≤ ONE_BTC*144`; stop at 5 inputs.
   (`getUtxoID = txHash ‖ int_to_binary(txOutIndex)` minimal LE bytes.)

Because methods 8 and 9 are random and dict order matters in method 4, results are not
reproducible bit-for-bit; a Rust port should either seed/fix these or document that
selection is not part of any compatibility contract.

### 4.6 Fee estimation

| Function | Formula | Used by |
|---|---|---|
| `estimateFee()` CS:727-741 | `MIN_TX_FEE` (10 000) unless Core RPC `estimatefee(3)` > 0, then `int(fee*ONE_BTC)` (BTC/kB → sat/kB) | `calcMinSuggestedFees*` |
| `estimatePriority()` CS:745-760 | `DEFAULT_PRIORITY = 57 600 000`; adopts the RPC `estimatepriority(3)` value **only if it equals −1** (inverted condition, CS:752) | `calcMinSuggestedFees*` |
| `calcMinSuggestedFees(sel, target, preFee, nRecip)` CS:794-825 | `change = Σsel − (target+preFee)`; `numBytes = 10 + 180*nIn + 35*(nRecip + (1 if change>0))`; `numKb = numBytes//1000`; `fee = (1+numKb)*estimateFee()`; if `numKb > 10` return fee; `prio = Σ(val*conf)//numBytes`; if `estPrio > −1 and prio ≥ estPrio and numBytes < 10000` → **0**; else fee. Empty selection → −1 | GUI (non-lockbox) |
| `calcMinSuggestedFeesHackMS(...)` CS:763-790 | `numBytes = Σ(M*70+40 over inputs via getMultisigScriptInfo(utxo script)) + 200*nRecip`; rest as above (no −1 guard). For P2SH prevouts `getMultisigScriptInfo` returns M=0 → 40 bytes/input | GUI (lockbox spend) |
| `calcMinSuggestedFeesNew(sel, svPairs, preFee, changeScript)` CS:877-936 | `numBytes = 10 + Σ(len(script)+9 over outputs) + (len(changeScript) or 35 if change>0)` — **inputs are not counted**; `numKb>10` → `[(1+numKb)*MIN_RELAY_TX_FEE, (1+numKb)*MIN_TX_FEE]`; free (`[0,0]`) if not dust, `prio ≥ ONE_BTC*144/250.`, `numBytes < 10000`; else `(1+numKb) * [MIN_RELAY_TX_FEE, MIN_TX_FEE]` | armoryd |
| `approxTxInSizeForTxOut(script, lboxList)` CS:841-863 | P2PKH 180, P2PK 110, multisig `M*70+40`, P2SH-of-known-lockbox `M*70+40`, unknown 1650 | (helpers) |

Fee policy constants: relay/min fee 10 000 sat per (started) kB; "dust" for fee purposes
is any output < `CENT` (1 000 000 sat) — this is the pre-0.9 Core rule, not the modern
`dustRelayFee` rule. There is no notion of feerate in sat/vB.

### 4.7 GUI send flow (`SendBitcoinsFrame.validateInputsGetUSTX`, TF:423-781)

1. Per recipient row: address/lockbox string → script via `FUNC_GETSCRIPT` (P2PKH,
   P2SH, lockbox `Lockbox[...]` strings, see spec 04); invalid rows are highlighted;
   wrong-network detection via `addrStr_to_hash160` prefix.
2. Amount via `str2coin(negAllowed=False)`: 0 → error; negative, >8 decimals, empty →
   specific errors. Comment column (max 144 chars, TF:1042).
3. Warn if a P2SH lockbox recipient is "non-standard to spend" (`isMofNNonStandardToSpend`:
   `(n>3 and m>3) or (n>4 and m>2) or (n>5 and m>1) or n>6`, MultiSigUtils.py:227-236).
4. Fee from the fee box (`Default_Fee` setting, default `MIN_TX_FEE`, TF:44).
5. `totalSend + fee > balance` → "Insufficient Funds" (coin-control balance if active).
6. Fee loop (TF:595-610): `feeTry = fee`; repeat `utxoSelect = PySelectCoins(utxos,
   totalSend, feeTry)`; `minFee = calcMinSuggestedFees(...)` (or `HackMS` for lockboxes)
   while `feeTry < minFee and totalSend + minFee ≤ bal` (set `feeTry = minFee`).
7. `minFee > 99*MIN_RELAY_TX_FEE` → error "too many small inputs" (TF:613-620).
8. `fee < minFee` → Yes (use minFee) / No (keep user fee) / Cancel dialog (TF:623-680).
9. `fee > 100*MIN_RELAY_TX_FEE` or `fee > 10*minFee (minFee>0)` → "Excessive Fee" confirm.
10. Empty selection → "Coin Selection Error".
11. `change = Σsel − (totalSend + fee)`; if > 0 append change output from
    `determineChangeScript` (TF:882-930):
    * default (non-Expert or "use default" unchecked): **new address**
      (`getNextUnusedAddress`, comment `'[[ Change received ]]'`, qtdefines.py:40); for a
      lockbox, change → the lockbox's P2SH script.
    * Expert options: `Feedback` = script of `utxoSelect[0]` (first selected input);
      `Specify` = user-entered address/script. "Remember" stores `ChangeBehavior` /
      `ChangeAddr` wallet settings. Change of any size > 0 is created (no dust check).
12. **Outputs are `random.shuffle`d** (TF:732) — change position is random.
13. Build USTX via `createFromTxOutSelection` (pubKeyMap from wallet for single-sig;
    lockbox: `p2shMap`, `contribID = lockbox ID` on inputs and on outputs equal to the
    lockbox script).
14. If "Create Unsigned" is checked → show/save the `TXSIGCOLLECT` block (offline
    flow); else `DlgConfirmSend`, unlock, `wlt.signUnsignedTx`, `getSignedPyTx`, store
    comment on the txid (`wlt.setComment(txHash, ...)`; multiple recipients joined as
    `"<comment> (<approx amt>);  "`), `broadcastTransaction` (TF:783-832).

Other send-dialog features: multiple recipients (add/remove rows), "MAX" button =
`balance − fee − Σother amounts` (TF:933-969), donation row (`ARMORY_DONATION_ADDR`,
0.05 BTC, TF:1096-1108), "Enter URI" fills a row from a `bitcoin:` URI (TF:1111-1142),
coin control (address subset + alt balance, TF:415-418).

Offline review/sign/broadcast frame (`SignBroadcastOfflineTxFrame`, TF:1318-1883):
parse block → `evaluateSigningStatus` + `verifySigsAllInputs` → enable Sign if the
wallet is relevant and not watching-only, Broadcast only if `canBroadcast` and all sigs
valid and online. Sign shows `DlgConfirmSend`, warns "Missing Change" if no output is to
this wallet and there are >1 outputs.

armoryd `create_unsigned_transaction` (armoryd.py:1925-2015): fee default 0;
`PySelectCoins(utxos, totalSend, fee)`; `minFeeRec = calcMinSuggestedFeesNew(...)[1]`;
if fee < minFeeRec: error if a fee was explicitly requested, else reselect with
`minFeeRec`; change → next unused address (or lockbox P2SH); shuffle; returns
`serializeAscii()`.

---

## 5. Message signing (`jasvet.py`, `ui/toolsDialogs.py`)

All message signing uses the pure-Python EC code in jasvet (not Crypto++), with a
**random** nonce from Crypto++ `GenerateRandom(32)` (`randomk`, JV:45-49), no RFC 6979,
no low-S. Only ASCII messages are allowed by the GUI (TD:136-182). The private key comes
from the Armory wallet (32 bytes → uncompressed, header 27-30).

### 5.1 Bitcoin-Qt compatible signature ("bare", `ASv0`, JV:635-636)

* Digest: `z = hash256(b"\x18Bitcoin Signed Message:\n" ‖ varint(len(msg)) ‖ msg)`
  (`format_msg_to_sign`, JV:430-431; `decvi` uses `< 0xffff` / `< 0xffffffff` bounds,
  JV:421-428 — off by one vs CompactSize for exactly 0xffff/0xffffffff, irrelevant here).
* Sign: `s = k⁻¹(z + r·x) mod n` (JV:383-395), r = (kG).x.
* Output 65 bytes: `header ‖ r(32 BE) ‖ s(32 BE)`, base64. `header = 27 + recid (+4 if
  compressed)`; recid found by trying 0..3 and keeping the first whose recovered
  address equals the signer's (JV:512-528).
* Secret of 33 bytes is treated as "compressed" (last byte dropped) (JV:486-497).

Verification (`verify_message_Bitcoin`, JV:444-484):

* base64 decode, must be 65 bytes; `27 ≤ header < 35`; `header ≥ 31` → compressed,
  subtract 4; `recid = header − 27`.
* `x = r + (recid/2)*n`; y from `sqrt_mod`; pick parity `(y − recid) % 2 == 0`;
  `Q = r⁻¹(sR − zG)`; return `addrStr(hash160(serialize(Q, compressed)), netByte)`.
* **It returns the recovered address — it does not check validity against an expected
  address.** Callers compare: bare-signature verifier requires `recovered ==
  user-entered address` (TD:303-314); the signed-block verifiers just display the
  recovered address (TD:345-353, armoryd.py:354-356, announcefetch.py:304-305). Any
  well-formed signature "verifies" to *some* address.
* `verifySignature(b64sig, msg, signVer, netByte)` (JV:629-633): `v1` first applies
  `FormatText(msg, sigctx=True)`.

### 5.2 Text normalization `FormatText(t, sigctx)` (JV:530-552)

For each `\n`-separated line: strip trailing `' '`, `'\r'`, `'\t'`; append `'\r'`; if
`sigctx == False` and the line starts with `'-'`, prefix `'- '` (dash-escape); join with
`'\n'`; drop the final 2 chars (`'\r\n'`). Net effect: lines joined by CRLF, trailing
whitespace removed, no trailing newline, dash-escaping only in display context.

### 5.3 Armory clearsign block (`ASv1CS`, JV:638-643)

The signature is over `FormatText(msg)` (**display context, i.e. dash-escaped**).

```
"-----BEGIN BITCOIN SIGNED MESSAGE-----\r\n"
"Comment: Signed by Bitcoin Armory v0.93.3\r\n"          # JV:41-42, getVersionString(BTCARMORY_VERSION, 3)
"\r\n"
FormatText(msg) "\r\n"
ASCIIArmory(sig65, "BITCOIN SIGNATURE")
```

### 5.4 Armory base64 block (`ASv1B64`, JV:645-647)

`ASCIIArmory(sig65 ‖ FormatText(msg), "BITCOIN MESSAGE", addComment=True)`.

### 5.5 `ASCIIArmory(block, name, addComment)` (JV:574-584)

```
"-----BEGIN " name "-----" "\r\n"
[ "Comment: Signed by Bitcoin Armory v0.93.3" ]           # only if addComment, no CRLF of its own
"\r\n\r\n"
base64(block) in 64-char lines joined by "\r\n"
"\r\n="  base64(crc24(block))  "\r\n"
"-----END " name "-----"                                  # no trailing newline
```

So without comment there are **two** empty lines after the BEGIN line; with comment,
one. `crc24` (JV:555-569) is the OpenPGP CRC-24 (init `0xB704CE`, poly `0x1864CFB`) but
the 3 bytes are emitted **least-significant byte first** (opposite of RFC 4880). Verified
on the testJasvet vector: emitted `=AnjN`; RFC 4880 order would be `=zXgC`.

### 5.6 Parsing signed blocks (`readSigBlock`, JV:586-627)

1. `r = FormatText(input, sigctx=True)` (normalizes to CRLF, strips trailing spaces).
2. `name` = text between the first `-----BEGIN ` and the next `-----`.
3. `BITCOIN MESSAGE`: body between BEGIN and END, split on `'\n='` into data/crc; data
   after the first `\r\n\r\n` (so the comment line is skipped), CRLFs removed,
   base64-decoded; CRC mismatch → `ChecksumError`; `sig = decoded[:65]`,
   `msg = decoded[65:]`.
4. `BITCOIN SIGNED MESSAGE`: message = text after the BEGIN marker, after the first
   `\r\n\r\n`, up to the first `\r\n-----` (so a message line beginning with `-----`
   would truncate — dash-escaping prevents that for `-` lines in Armory-produced
   blocks); signature = base64 between the second BEGIN and `'\n='`, CRC as above.
   **No dash-unescaping** — the signed bytes are the escaped text, which matches what
   `ASv1CS` signed.
5. Other names → `UnknownSigBlockType`.

Verification of a block: `verifySignature(sig, msg, 'v1', ADDRBYTE)`.

### 5.7 Legacy QD signature block (dead code)

`qtdialogs.makeSigBlock` / `readSigBlock(parent, packet)` (QD:7613-7716) define:

```
"-----BEGIN-SIGNATURE-BLOCK".ljust(63,'-') "\n"
"Address:    <addr>\n"
"Message:    \"<48 chars>\"\n" then "            \"<48 chars>\"\n" …
"PublicKey:  <50 hex>\n" + continuation lines indented 12 spaces
"Signature:  <50 hex>\n" + continuation lines
"-----END-SIGNATURE-BLOCK".ljust(63,'-') "\n"
```

Neither function has callers in 0.93.3 (grep), so this format is not produced or
accepted by any UI path. Listed for completeness only.

### 5.8 UI surface (`MessageSigningVerificationDialog`, TD:20-360)

Sign tab: address (wallet-owned, P2SH warns), message; buttons "Bare Signature"
(`ASv0` → base64 only), "Base64 Block" (`ASv1B64`), "Clearsign" (`ASv1CS`).
Verify tabs: bare (address + message + base64 sig; v0, must match address) and
"Signed Message Block" (either block type; v1; shows recovered signer, with special
display when the signer is Armory's announcement key `ANNOUNCE_SIGN_PUBKEY`).

---

## 6. `bitcoin:` URIs (AU:2890-2968; AQ:2626-2705, 4027-4100; QD:10040-10060)

### 6.1 `parseBitcoinURI(uriStr)` (AU:2893-2922)

1. `urlparse(uriStr)`; `parse_qs(uri.query)` (Python 2.7 `urlparse`): percent-decoding
   **and `'+' → ' '`**; repeated keys produce lists; single-valued lists are flattened.
2. Only if `scheme == 'bitcoin'`: `data['address'] = uri.path` (not validated here);
   for each query key: if `key.lower() == 'amount'` → `data['amount'] = str2coin(v)`
   (satoshis; a repeated `amount` → list → exception), else `data[key] = v` verbatim
   (case preserved, `req-` kept).
3. Non-`bitcoin` scheme → `{}`. Exceptions propagate (AQ wraps in try → `{}`).

Caller checks (`parseUriLink`, AQ:2626-2705): offline → refuse; empty dict →
"malformed"; no `address` → refuse; `checkAddrType(base58_to_binary(addr))` must be
`ADDRBYTE` or `P2SHBYTE` (bad checksum, −1, passes through here); any key starting with
`req-` whose suffix is not in `{address, version, amount, label, message}` → refuse.
`uriSendBitcoins` (AQ:4027-…) and the send dialog's "Enter URI" join `label` and
`message` as `label + ': ' + message` for the comment field.

### 6.2 `createBitcoinURI(addr, amt=None, msg=None)` (AU:2953-2968)

```
"bitcoin:" addr
[ "?" ]                               if amt or msg
[ "amount=" coin2str(amt, maxZeros=0).strip() ]   e.g. 1.5 BTC -> "1.5", 1 BTC -> "1", 10 BTC -> "10", 0.1 -> "0.1", 1 sat -> "0.00000001"
[ "&" ]                               if amt and msg
[ "label=" uriReservedToPercent(msg) ]
```

`coin2str` (AU:1248-1277) right-justifies to 18 chars, chops up to `ndec−maxZeros` trailing zeros (replaced by spaces) and finally deletes `'. '`, so whole-BTC amounts lose the decimal point (the `s.lstrip()` at AU:1270 discards its result). `uriReservedToPercent` (AU:2926-2935) replaces, in this order, each of
`% ! * ' ( ) ; : @ & = + $ , / ? # [ ] " <space>` with `%XX` (lowercase hex via
`int_to_hex`); `%` first to avoid double encoding. Non-ASCII is not encoded.
`uriPercentToReserved` (AU:2939-2949) decodes every `%XX`. Note the message is put in
`label=`, not `message=`. The "Create URI" dialog rejects `amt > MAX_SATOSHIS` (treated
as no amount) and requires `checkAddrStrValid(addr)` (QD:10040-10057).

---

## 7. Script / address helpers

### 7.1 C++ output script classification (`BtcUtils::getTxOutScriptType`, BTU:884-912)

Evaluated in this order; `s[-1]` = last byte:

| Enum (AU:517-522) | Value | Exact rule |
|---|---|---|
| — | | `len < 23` → NONSTANDARD |
| `CPP_TXOUT_STDHASH160` | 0 | `len == 25`, `76 a9 14 … 88 ac` |
| `CPP_TXOUT_STDPUBKEY65` | 1 | `len == 67`, `s[0]==0x41`, `s[1]==0x04`, `s[-1]==0xac` |
| `CPP_TXOUT_STDPUBKEY33` | 2 | `len == 35`, `s[0]==0x21`, `s[1] ∈ {02,03}`, `s[-1]==0xac` |
| `CPP_TXOUT_P2SH` | 4 | `len == 23`, `a9 14 … 87` |
| `CPP_TXOUT_MULTISIG` | 3 | `s[-1]==0xae` and `getMultisigPubKeyList` returns M>0: `s[0]` ∈ 81..96 (OP_1..OP_16), `s[-2]` ∈ 81..96, then N pushes each of size byte `0x41` or `0x21`. **Not checked**: M ≤ N, key validity, that the pushes end exactly at `s[-2]`. |
| `CPP_TXOUT_NONSTANDARD` | 5 | everything else (incl. OP_RETURN, segwit v0/v1 programs) |

Groups (AU:523-529): `CPP_TXOUT_HAS_ADDRSTR = {0,1,2,4}`, `CPP_TXOUT_STDSINGLESIG = {0,1,2}`.
Display names (AU:531-537): `Standard (PKH)`, `Standard (PK65)`, `Standard (PK33)`,
`Multi-Signature`, `Standard (P2SH)`, `Non-Standard`.

### 7.2 scrAddr (`getTxOutScrAddr`, BTU:999-1036)

| Type | scrAddr |
|---|---|
| P2PKH | `00 ‖ script[3:23]` |
| P2PK65 / P2PK33 | `00 ‖ hash160(pubkey)` (so P2PK and P2PKH of the same key share a scrAddr) |
| P2SH | `05 ‖ script[2:22]` |
| Multisig | `fe ‖ M ‖ N ‖ sorted(hash160(pk_i))…` (`getMultisigUniqueKey`, BTU:1066-1086) |
| Non-standard | `ff ‖ hash160(script)` |

Python: `script_to_scrAddr`, `scrAddr_to_script` (P2PKH/P2SH only, AU:1529-1552),
`scrAddr_to_addrStr` (P2PKH/P2SH only; others raise `BadAddressError`, AU:1565-1581),
`addrStr_to_scrAddr`/`addrStr_to_script` (AU:1591-1607; note `BadAddressError(...)`
objects are constructed but **not raised** at AU:1593 and AU:1601 — an invalid address
returns `None` silently), `getHash160ListFromMultisigScrAddr` (TX:364-372).

`getTxOutScriptDisplayStr` (TX:380-391): address for `HAS_ADDRSTR`;
`'[Multisig M-of-N] (not P2SH but would be <p2sh addr>)'`; else
`'[Non-Standard Script: <hex of scrAddr[1:65]>]: '`.

### 7.3 Input script classification (`getTxInScriptType`, BTU:925-967; AU:540-555)

| Enum | Value | Rule (in order) |
|---|---|---|
| `CPP_TXIN_NONSTANDARD` | 6 | empty script |
| `CPP_TXIN_COINBASE` | 2 | prev hash all zero |
| `CPP_TXIN_SPENDP2SH` | 5 | last push parses as a *standard* output script type |
| `CPP_TXIN_SPENDMULTI` | 4 | `script[0]==0`, push-only, `script[2]==0x30 && script[4]==0x02` |
| `CPP_TXIN_SPENDPUBKEY` | 3 | `script[1]==0x30, script[3]==0x02`, `len == script[2]+4` |
| `CPP_TXIN_STDUNCOMPR` | 0 | `len == sigSize + 66` |
| `CPP_TXIN_STDCOMPR` | 1 | `len == sigSize + 34` |

Helpers: `TxInExtractAddrStrIfAvail` (TX:423-435; P2PKH → address of hash160(last push);
P2SH → `binScript_to_p2shAddrStr(lastPush)`), `TxInExtractPreImageIfAvail` (TX:438-447;
uses `scrType == [list]` so it **always returns `''`**), `getTxInP2SHScriptType`
(TX:405-420).

### 7.4 Script builders

* `hash160_to_p2pkhash_script(h20)` → `76 a9 14 h20 88 ac` (AU:1446-1458; non-20 →
  `InvalidHashError`).
* `hash160_to_p2sh_script(h20)` → `a9 14 h20 87`; `script_to_p2sh_script(s)` =
  `hash160_to_p2sh_script(hash160(s))` (AU:1463-1479).
* `pubkey_to_p2pk_script(pk)` → `push(pk) ac`, pk must be 33/65 bytes (AU:1484-1494).
* `pubkeylist_to_multisig_script(pkList, M, withSort=True)` → `OP_M ‖ (len‖pk)… ‖ OP_N ‖
  ae`; keys **sorted lexicographically by raw bytes** by default (AU:1508-1526).
* `scriptPushData(d)` (SC:82-94):
  `len ≤ 76` → `len ‖ d`; `len ≤ 256` → `4c ‖ len ‖ d`; `len ≤ 65536` → `4d ‖ u16le ‖ d`;
  else constructs (does not raise) an error and returns `None`.
  **Bugs**: a 76-byte push is emitted as `4c ‖ data` (0x4c is OP_PUSHDATA1, so the result
  is mis-parsed); 256 is emitted as `4c 00 01 …` (two length bytes, since
  `int_to_binary` doesn't truncate); 65536 likewise. Signatures (≤73), pubkeys (33/65) and
  multisig redeem scripts up to 3-of-3 uncompressed (201 bytes) are unaffected. A Rust
  port should emit minimal pushes (`<76` direct, `≤255` PUSHDATA1, `≤65535` PUSHDATA2)
  — identical output for all sizes Armory actually produces.
* `ScriptBuilder` (SC:96-120), `convertScriptToOpStrings` (SC:20-72; PUSHDATA4 branch is
  broken).

### 7.5 Opcode tables

`opnames` / `opCodeLookup` (TX:28-300): full legacy table 0..175 (OP_0 … OP_CHECKMULTISIGVERIFY).
Nothing above 175: OP_NOP1-10, CLTV (0xb1), CSV (0xb2), OP_CHECKSIGADD (0xba) are absent.

---

## 8. Fixture check (tiab golden files)

Directory: `pytest/tiab.zip` → `tiab/armory/` (e.g. `tiab/armory/armory_8gRmZv48_.signed.tx`, 950 bytes in the zip listing); byte-identical copies are checked in at `fixtures/legacy/`.
All four files: CRLF line endings, 80-char header/footer and base64 lines, testnet magic
`0b110907`, all inputs P2PKH with uncompressed keys.

### 8.1 `armory_8gRmZv48_.signed.tx` (G2, fully decoded)

Verbatim file (CRLF shown as line breaks):

```
=====TXSIGCOLLECT-8gRmZv48======================================================
AQAAAAsRCQcAAAAAAf3EAQEAAAALEQkHchUHvHxM29fPeY02InKy5ZQeYZ8vMA9GrJVpM8tCGBEAAAAA
/QEBAQAAAAEhOzQQbizqkYkkOvs8sxROO1j198R/ls8zebRCTgGNagMAAACMSTBGAiEA5nWwoKcAU7g3
dhs/5dkq6eaw+yY7T+uJiqKbnmjwkjACIQCARNrs4jaNx5iNFPyObj05olSK710suLl+YbfKe8ihUgFB
BM3zuTqCoy/uKAh0Kgn5LeWNYpMv/WJvqUsJYT2+/QtuG73EQhswCxN7aqyOaOF8EHN7mLUT93p9G0st
eWtEUof/////AlA/R9wVAAAAGXapFCOOhZJjttO/Z1siFJighsAM3huMiKwAypo7AAAAABepFEsgPEt7
f4VFiKFCrGqixxSWvpZVhwAAAAAAAAD/////AUEEYjJpOVJcaXeB3CgM2Apdk/GpLtSA4wrfvuvhsbwe
Fhs/BqIi3MpiugRcdTbTox3iVUhCpYonBrmWu9/jvMRqj0gwRQIgBF6DgTlzlxdC6HoAodrl3gJHXsTZ
ERNz13ysiyKzDdgCIQCVztcBtev+Qb8ypVHpT80lQYm2OG9+uq4GwizWGqk7KAEAAjQBAAAACxEJBxl2
qRS+x3gsemhrYDAPeDEDLSdAKIs/uIisQE6soBUAAAAAAAROT05FAAAANAEAAAALEQkHGXapFNLxy21s
7kg7nBjG6/43HTetOBsEiKwAypo7AAAAAAAABE5PTkUAAAA=
================================================================================
```

Decoded (575 bytes):

```
USTX  version=1  magic=0b110907  lockTime=0  nIn=1  nOut=2
  USTXI[0] (len 0x1c4=452)
    version=1 magic=0b110907
    outpoint = 111842cb336995ac460f302f9f611e94e5b27222368d79cfd7db4c7cbc071572 (BE) : 0
    supportTx = 257 bytes, hash256 == outpoint hash  ✔
      prevout[0]: value 93 889 970 000, script 76a914238e859263b6d3bf675b221498a086c00cde1b8c88ac (P2PKH)
    p2shScript='' contribID='' contribLabel='' sequence=0xffffffff N=1
    key[0] pub = 0462326939525c697781dc280cd80a5d93f1a92ed480e30adfbeebe1b1bc1e161b3f06a222dcca62ba045c7536d3a31de2554842a58a2706b996bbdfe3bcc46a8f
           (testnet addr mikxgMUqkk6Tts1D39Hhx6wKEeQbBH3ons; hash160 = 238e85…1b8c ✔)
           sig = 30450220045e83813973971742e87a00a1dae5de02475ec4d9111373d77cac8b22b30dd802210095ced701b5ebfe41bf32a551e94fcd254189b6386f7ebaae06c22cd61aa93b2801
                 hashtype 01, **high-S**, ECDSA-valid against our SIGHASH_ALL preimage ✔
           wltLoc = ''
  DTXO[0] version=1 script 76a914bec7782c7a686b60300f7831032d2740288b3fb888ac value 92 889 960 000
          p2sh='' wltLoc='' authMethod='NONE' authData='' contribID='' contribLabel=''   (mxuhdt2rHapgcieARJKUiLLLBeBRh7AQG5)
  DTXO[1] version=1 script 76a914d2f1cb6d6cee483b9c18c6ebfe371d37ad381b0488ac value  1 000 000 000   (mzkKrXNPU6nfBpZCKLmwueb9MvSFaKPDMD)
fee = 10 000 sat
unsigned tx = 0100000001721507bc7c4cdbd7cf798d362272b2e5941e619f2f300f46ac956933cb4218110000000000ffffffff02404eaca0150000001976a914bec7782c7a686b60300f7831032d2740288b3fb888ac00ca9a3b000000001976a914d2f1cb6d6cee483b9c18c6ebfe371d37ad381b0488ac00000000
computed ID = base58(hash256(unsigned tx))[:8] = 8gRmZv48  == header ✔
```

Finalized per §1.6 (low-S re-encoding changes the sig to
`30440220045e…0dd802206a3128fe4a1401be40cd5aae16b032d9792526ae3fc9e58db91031b6b58d061901`):

```
0100000001721507bc7c4cdbd7cf798d362272b2e5941e619f2f300f46ac956933cb421811000000008a4730440220045e83813973971742e87a00a1dae5de02475ec4d9111373d77cac8b22b30dd802206a3128fe4a1401be40cd5aae16b032d9792526ae3fc9e58db91031b6b58d061901410462326939525c697781dc280cd80a5d93f1a92ed480e30adfbeebe1b1bc1e161b3f06a222dcca62ba045c7536d3a31de2554842a58a2706b996bbdfe3bcc46a8fffffffff02404eaca0150000001976a914bec7782c7a686b60300f7831032d2740288b3fb888ac00ca9a3b000000001976a914d2f1cb6d6cee483b9c18c6ebfe371d37ad381b0488ac00000000
txid (BE) = 347f1b745b3b7fb38bbec2af070f31cc567cedf41693008ae451950d77a3d5d0   (257 bytes)
```

(A 2014 Armory would have broadcast the high-S form; the txid above is what 0.93.3
produces.)

### 8.2 `Simulfund_fmuHCs5G.sigcollect.tx` (G2, 1456 bytes, unsigned simulfund)

ID `fmuHCs5G` recomputes ✔. lockTime 0, fee 30 000 000. Inputs (all P2PKH, seq ffffffff,
supportTx hash ✔, no sigs):

| # | outpoint (BE:idx) | value | contribID / label | key (testnet addr) |
|---|---|---|---|---|
| 0 | db0ee46b…ceee4:0 | 2 000 000 000 | `3NFePKw5` / `ThirdFunder` | mpXd2u8fPVYdL1Nf9bZ4EFnqhkNyghGLxL |
| 1 | c742fb5c…cc0db:1 | 3 000 000 000 | `4f71oDhA` / `SecondFunder` | mhbmvVedo4i67maX6pfw9trcBWQQ3yXgkB |
| 2 | c742fb5c…cc0db:0 | 94 999 980 000 | `J75shT7q` / `FirstFunder` | mnDAmv621M47aUnepTe5Bn1LrA1EnCnyoZ |

Outputs: P2SH `a914e6abea43805995a9b88664bc3a948b043e8a3d1187` 300 000 000
(2NEGuMGuJ4meQsUCMYPT9qmCZtpXAKCicu4, contribID ''), then change P2PKH 1 890 000 000
(`3NFePKw5`), 2 890 000 000 (`4f71oDhA`), 94 889 980 000 (`J75shT7q`); all
`authMethod='NONE'`, `contribLabel=''` (DTXO labels are not set by simulfund — spec 04).

### 8.3 `armory_Ev9L4wAd_.signed.tx` and `armory_EyUJNfMQ_.unsigned.tx` (G1)

Both decode only with the G1 layout (no `contribLabel` in USTXI or DTXO); the 0.93.3
parser rejects them. Header ID of **both** is `Ev9L4wAd` and recomputes ✔. 1 input
(d23615f4…47b5:1, value 249 999 980 000, pub `040af913…2bb3`, testnet
`mq7Zr1WEcJ2hKPNMGHuuHDqvKcKYCWscXW`), outputs 1 000 000 000 →
`my3RgbjyE2WHpqd7v2vJHzRaLPQ81axeyk`, 248 999 970 000 →
`mkMHuajoCSFM5EnLB22ZD8poSWHMVLGkPy`; fee 10 000. Signed file sig
`3044022069ad…db5d8022036eb…eafe01` is low-S and valid ✔.

### 8.4 Test blocks in `pytest/testMultisig.py` (decoded with the same tool)

| Block (line) | Gen | ID ✔ | Content | Sig checks |
|---|---|---|---|---|
| `asc_nosig` (269), `asc_sig` (287) | G0 | `5JxmLy4T` | 1 P2PKH in → bare 2-of-3 multisig 42 500 000 + P2PKH change | sig valid ✔ |
| `regular` (521) | G2 | `8rgLHcFg` | 2 P2PKH ins (one high-S sig) | both valid ✔ |
| `multispend_unsigned/partsign/enoughsign/oversign` (548/568/589/611) | G2 | `7oXWAFds` | 1 **P2SH 2-of-3** in (contribID `7mtvkCTa`), 3 key slots; 0/1/2/3 sigs | all present sigs valid using the **redeem script** as subscript ✔ |
| `ss2ms_unsigned/signed` (634/648) | G2 | `HJqTvsXR` | P2PKH → P2SH lockbox | valid ✔ |

Finalized txids (low-S, stripExtraSigs): `enoughsign` →
`29f8cbb4b3d7c9e3f6855f7f002d119a0469eabba272a98fdb424af2892561f2` (468 B);
`oversign` (slot 2's sig dropped) →
`7aa88ad8e62491c5fbb8483bdf53bd956fc58cdcec8772171bef30eadbda2cba` (467 B);
`regular` → `486ba6f2408ca473f43f5966841dd77b9db9a2abd7afc637f77b2ca5fff6e83c`;
`ss2ms_signed` → `5fac1948b4f5468a0ddf5e23afcf0a7a4ce29c81a4a724653f14ffbb39395d9b`.

`oversign` final raw tx (P2SH multisig sigScript reference):

```
01000000014a8c2419d384b999e909ec54af1b2a21a69b11965810d651740ff7b05fd2ece801000000fd5c010047304402204a75b9fa5f808e73d57c1c67d8bc07bc7b5f02779a45320aae7a6ce72e3d39aa02201ea14334677b3aa12a9a4c158e2dcea58abe84d79fa445a02df7ad8e8de60b830147304402202b452a41264206d684eaf40843377672ec7b942633e45f563ac4ad997b80cbfe02201a2057a38b44cfd6f086b89dcf26f89a679d081587efcbb4ef0e68d5b87aff3e014cc952410423214f61ebd268d190dbbe551f89151733af013e13e15bcdde65fd73421c90ba8bada58951154676acb616100a3885b2fdb2630f4737a2f1c0eebe79078129014104c594e7e0dff507907c8d22f9344d5e22269ce1b3a080325462a11296b6d2e37de6dede10dfa039a8a9a499866c5c507b0d02d4b4ea9549f80b8a1a348c0392ba4104ce15d8d12bfdbe86bd34578891165cc35cc4b42e5ddf4fea89f58487e75f48513b08be141e9ce0d13117975db7c999c0b150f8373764d0bcb5fb888d86468da353aeffffffff02706f9800000000001976a914277c56c45954152a32842920000f8251bd57202288ac809698000000000017a9149416dec5a7cdeb7a3baf0ba14f787532cc7e91428700000000
```

(Slot 0's sig was high-S in the USTX and appears low-S here: `…02201ea14334…`.)

---

## 9. Test vectors (verbatim, with sources)

### 9.1 Raw transactions — pytest/testPyTX.py:24-41 (identical copies in testMultisig.py:35-53)

```python
tx1raw = hex_to_binary( \
   '01000000016290dce984203b6a5032e543e9e272d8bce934c7de4d15fa0fe44d'
   'd49ae4ece9010000008b48304502204f2fa458d439f957308bca264689aa175e'
   '3b7c5f78a901cb450ebd20936b2c500221008ea3883a5b80128e55c9c6070aa6'
   '264e1e0ce3d18b7cd7e85108ce3d18b7419a0141044202550a5a6d3bb81549c4'
   'a7803b1ad59cdbba4770439a4923624a8acfc7d34900beb54a24188f7f0a4068'
   '9d905d4847cc7d6c8d808a457d833c2d44ef83f76bffffffff0242582c0a0000'
   '00001976a914c1b4695d53b6ee57a28647ce63e45665df6762c288ac80d1f008'
   '000000001976a9140e0aec36fe2545fb31a41164fb6954adcd96b34288ac00000000')
tx2raw = hex_to_binary( \
   '0100000001f658dbc28e703d86ee17c9a2d3b167a8508b082fa0745f55be5144'
   'a4369873aa010000008c49304602210041e1186ca9a41fdfe1569d5d807ca7ff'
   '6c5ffd19d2ad1be42f7f2a20cdc8f1cc0221003366b5d64fe81e53910e156914'
   '091d12646bc0d1d662b7a65ead3ebe4ab8f6c40141048d103d81ac9691cf13f3'
   'fc94e44968ef67b27f58b27372c13108552d24a6ee04785838f34624b294afee'
   '83749b64478bb8480c20b242c376e77eea2b3dc48b4bffffffff0200e1f50500'
   '0000001976a9141b00a2f6899335366f04b277e19d777559c35bc888ac40aeeb'
   '02000000001976a9140e0aec36fe2545fb31a41164fb6954adcd96b34288ac00000000')
```

Expected (testMultisig.py:131-134): `tx1hash (BE) = aa739836a44451be555f74a02f088b50a867b1d3a2c917ee863d708ec2db58f6`,
`tx2hash (BE) = 9072559e9e2772cd6ac88683531a512cba6c2fee82b2476ed5e84c24abe5f526` (recomputed ✔).
Round-trip `serialize(unserialize(x)) == x` (testPyTX.py:309-320).

Larger vectors — copy from source (multi-line, whitespace-separated hex); the txid
(BE, recomputed in Python 3) is given as a checksum for the extraction:

| Name | testPyTX.py lines | bytes | nIn/nOut | txid (BE) |
|---|---|---|---|---|
| `multiTx1raw` | 43-56 | 798 | 4/2 | `3b00cbfddde83577f7482bfa69b3d1638cfc8b2029f18cc9b3862a766c2cbbec` |
| `multiTx2raw` (input 3 has a non-canonical `220000fb…` r) | 58-71 | 799 | 4/2 | `325e917f526dabb8a9b3a9df250ebed0b0e84bbe70e4984fde2bc4b842e5d5b4` |
| `multiSig2of3` (in 0 bare 2-of-3, ins 1-2 P2SH 2-of-3) | 75-113 | 1191 | 3/1 | `b83c5f332673c5b6c13bc788e5678cf577f0957883b49fd4f72876a9de995aad` |
| `multiSig7of7` | 117-169 | 1648 | 2/2 | `190a8ede65fbb3e9dc22ca742c8b322a276706521e2b76216f5f0a0596618b96` |
| `tx1Fake` (also testMultisig.py:104-111) | 194-201 | 193 | 1/2 | `6ea8e72e97f655c3707e6d7c2be159ac21d01082ba2c8697624ab638da37b8a5` |
| `tx2Fake` (spends `tx1Fake`:1; also testMultisig.py:113-120) | 203-211 | 225 | 1/1 | `9112f5ed8e4dd757b88ade3da06eeedad68be50043d5a2f029f518869c33683b` |
| `hexBlock` (full block, round-trip + merkle root) | 173-190 | | | |

Script-evaluation pairs (`PyScriptProcessor.setTxObjects(tx1, tx2, 0)` then
`verifyTransactionValid()` must be True; tx2 input 0 spends a non-standard
multisig-style output of tx1). Verbatim from testPyTX.py:

`test2of2MultiSigTx` (testPyTX.py:377-379) — tx1 txid `2df3050037b3289ca97f690867674bfafbe664c6ceee88fae72b910a6508961c`, tx2 txid `9a4aae975ad50d6585c41442337231d474e782448e79d0bc12df4754a5198335`:

```
tx1 = 010000000189a0022c8291b4328338ec95179612b8ebf72067051de019a6084fb97eae0ebe000000004a4930460221009627882154854e3de066943ba96faba02bb8b80c1670a0a30d0408caa49f03df022100b625414510a2a66ebb43fffa3f4023744695380847ee1073117ec90cb60f2c8301ffffffff0210c18d0000000000434104a701496f10db6aa8acbb6a7aa14d62f4925f8da03de7f0262010025945f6ebcc3efd55b6aa4bc6f811a0dc1bbdd2644bdd81c8a63766aa11f650cd7736bbcaf8ac001bb7000000000043526b006b7dac7ca914fc1243972b59c1726735d3c5cca40e415039dce9879a6c936b7dac7ca914375dd72e03e7b5dbb49f7e843b7bef4a2cc2ce9e879a6c936b6c6ca200000000
tx2 = 01000000011c9608650a912be7fa88eecec664e6fbfa4b676708697fa99c28b3370005f32d01000000fd1701483045022017462c29efc9158cf26f2070d444bb2b087b8a0e6287a9274fa36fad30c46485022100c6d4cc6cd504f768389637df71c1ccd452e0691348d0f418130c31da8cc2a6e8014104e83c1d4079a1b36417f0544063eadbc44833a992b9667ab29b4ff252d8287687bad7581581ae385854d4e5f1fcedce7de12b1aec1cb004cabb2ec1f3de9b2e60493046022100fdc7beb27de0c3a53fbf96df7ccf9518c5fe7873eeed413ce17e4c0e8bf9c06e022100cc15103b3c2e1f49d066897fe681a12e397e87ed7ee39f1c8c4a5fef30f4c2c60141047cf315904fcc2e3e2465153d39019e0d66a8aaec1cec1178feb10d46537427239fd64b81e41651e89b89fefe6a23561d25dddc835395dd3542f83b32a1906aebffffffff01c0d8a700000000001976a914fc1243972b59c1726735d3c5cca40e415039dce988ac00000000
```

`test2of3MultiSigTx` (testPyTX.py:385-387) — tx1 txid `e232e0055dbdca88bbaa79458683195a0b7c17c5b6c524a8d146721d4d4d652f`, tx2 txid `a1c8a7c558835f45d9f584934f2602f444efb0467940cf83eadc97199326c909`:

```
tx1 = 010000000371c06e0639dbe6bc35e6f948da4874ae69d9d91934ec7c5366292d0cbd5f97b0010000008a47304402200117cdd3ec6259af29acea44db354a6f57ac10d8496782033f5fe0febfd77f1b02202ceb02d60dbb43e6d4e03e5b5fbadc031f8bbb3c6c34ad307939947987f600bf01410452d63c092209529ca2c75e056e947bc95f9daffb371e601b46d24377aaa3d004ab3c6be2d6d262b34d736b95f3b0ef6876826c93c4077d619c02ebd974c7facdffffffffa65aa866aa7743ec05ba61418015fc32ecabd99886732056f1d4454c8f762bf8000000008c493046022100ea0a9b41c9372837e52898205c7bebf86b28936a3ee725672d0ca8f434f876f0022100beb7243a51fbc0997e55cb519d3b9cbd59f7aba68d80ba1e8adbb53443cda3c00141043efd1ca3cffc50638031281d227ff347a3a27bc145e2f846891d29f87bc068c27710559c4d9cd71f7e9e763d6e2753172406eb1ed1fadcaf9a8972b4270f05b4ffffffffd866d14151ee1b733a2a7273f155ecb25c18303c31b2c4de5aa6080aef2e0006000000008b483045022052210f95f6b413c74ce12cfc1b14a36cb267f9fa3919fa6e20dade1cd570439f022100b9e5b325f312904804f043d06c6ebc8e4b1c6cd272856c48ab1736b9d562e10c01410423fdddfe7e4d70d762dd6596771e035f4b43d54d28c2231be1102056f81f067914fe4fb6fd6e3381228ee5587ddd2028c846025741e963d9b1d6cf2c2dea0dbcffffffff0210ef3200000000004341048a33e9fd2de28137574cc69fe5620199abe37b7d08a51c528876fe6c5fa7fc28535f5a667244445e79fffc9df85ec3d79d77693b1f37af0e2d7c1fa2e7113a48acc0d454070000000061526b006b7dac7ca9143cd1def404e12a85ead2b4d3f5f9f817fb0d46ef879a6c936b7dac7ca9146a4e7d5f798e90e84db9244d4805459f87275943879a6c936b7dac7ca914486efdd300987a054510b4ce1148d4ad290d911e879a6c936b6c6ca200000000
tx2 = 01000000012f654d4d1d7246d1a824c5b6c5177c0b5a1983864579aabb88cabd5d05e032e201000000fda0014730440220151ad44e7f78f9e0c4a3f2135c19ca3de8dbbb7c58893db096c0c5f1573d5dec02200724a78c3fa5f153103cb46816df46eb6cfac3718038607ddec344310066161e01410459fd82189b81772258a3fc723fdda900eb8193057d4a573ee5ad39e26b58b5c12c4a51b0edd01769f96ed1998221daf0df89634a7137a8fa312d5ccc95ed8925483045022100ca34834ece5925cff6c3d63e2bda6b0ce0685b18f481c32e70de9a971e85f12f0220572d0b5de0cf7b8d4e28f4914a955e301faaaa42f05feaa1cc63b45f938d75d9014104ce6242d72ee67e867e6f8ec434b95fcb1889c5b485ec3414df407e11194a7ce012eda021b68f1dd124598a9b677d6e7d7c95b1b7347f5c5a08efa628ef0204e1483045022074e01e8225e8c4f9d0b3f86908d42a61e611f406e13817d16240f94f52f49359022100f4c768dd89c6435afd3834ae2c882465ade92d7e1cc5c2c2c3d8d25c41b3ea61014104ce66c9f5068b715b62cc1622572cd98a08812d8ca01563045263c3e7af6b997e603e8e62041c4eb82dfd386a3412c34c334c34eb3c76fb0e37483fc72323f807ffffffff01b0ad5407000000001976a9146a4e7d5f798e90e84db9244d4805459f8727594388ac00000000
```

`testMultiSig` (testPyTX.py:393-395) — tx1 txid `87abda4755e492de6149affbfc67d42a367f76c166c6bc31c8dfb916f74f66bb`, tx2 txid `a17b21f52859ed326d1395d8a56d5c7389f5fc83c17b9140a71d7cb86fdf0f5f`:

```
tx1 = 0100000001845ad165bdc0f9b5829cf5a594c4148dfd89e24756303f3a8dabeb597afa589b010000008b483045022063c233df8efa3d1885e069e375a8eabf16b23475ef21bdc9628a513ee4caceb702210090a102c7b602043e72b34a154d495ac19b3b9e42acb962c399451f2baead8f4c014104b38f79037ad25b84a564eaf53ede93dec70b35216e6682aa71a47cefa2996ec49acfbb0a8730577c62ef9a7cc20c740aaaaee75419bef9640a4216c2b49c42d3ffffffff02000c022900000000434104c08c0a71ccbe838403e3870aa1ab871b0ab3a6014b0ba41f6df2b9aefea73134ecaa0b27797620e402a33799e9047f86519d9e43bbd504cf753c293752933f4fac406f40010000000062537a7652a269537a829178a91480677c5392220db736455533477d0bc2fba65502879b69537a829178a91402d7aa2e76d9066fb2b3c41ff8839a5c81bdca19879b69537a829178a91410039ce4fdb5d4ee56148fe3935b9bfbbe4ecc89879b6953ae00000000
tx2 = 0100000001bb664ff716b9dfc831bcc666c1767f362ad467fcfbaf4961de92e45547daab8701000000fd190100493046022100d73f633f114e0e0b324d87d38d34f22966a03b072803afa99c9408201f6d6dc6022100900e85be52ad2278d24e7edbb7269367f5f2d6f1bd338d017ca460008776614401473044022071fef8ac0aa6318817dbd242bf51fb5b75be312aa31ecb44a0afe7b49fcf840302204c223179a383bb6fcb80312ac66e473345065f7d9136f9662d867acf96c12a42015241048c006ff0d2cfde86455086af5a25b88c2b81858aab67f6a3132c885a2cb9ec38e700576fd46c7d72d7d22555eee3a14e2876c643cd70b1b0a77fbf46e62331ac4104b68ef7d8f24d45e1771101e269c0aacf8d3ed7ebe12b65521712bba768ef53e1e84fff3afbee360acea0d1f461c013557f71d426ac17a293c5eebf06e468253e00ffffffff0280969800000000001976a9140817482d2e97e4be877efe59f4bae108564549f188ac7015a7000000000062537a7652a269537a829178a91480677c5392220db736455533477d0bc2fba65502879b69537a829178a91402d7aa2e76d9066fb2b3c41ff8839a5c81bdca19879b69537a829178a91410039ce4fdb5d4ee56148fe3935b9bfbbe4ecc89879b6953ae00000000
```

### 9.2 USTXI / signature vector — pytest/testMultisig.py:136-142, 155-200

```python
self.pubKey = hex_to_binary( \
   '048d103d81ac9691cf13f3fc94e44968ef67b27f58b27372c13108552d24a6ee04'
     '785838f34624b294afee83749b64478bb8480c20b242c376e77eea2b3dc48b4b')
self.sigStr  = hex_to_binary( \
   '304602210041e1186ca9a41fdfe1569d5d807ca7ff'
   '6c5ffd19d2ad1be42f7f2a20cdc8f1cc0221003366b5d64fe81e53910e156914'
   '091d12646bc0d1d662b7a65ead3ebe4ab8f6c4' + '01')
```

* `UnsignedTxInput(tx1raw, 1, None, pubKey)`; `verifyTxSignature(tx2, sigStr, pubKey)` and
  `(tx2, sigStr)` → True; `badSig = sigStr[:16] + '\x00'*8 + sigStr[24:]` → False
  (testMultisig.py:163-183). Recomputed: z = `0x8ef805c5d2ec78f2a6b500c20df31ea2282ce67b181cdd11f7329b37f4f4478`, valid ✔.
* `insertSignatureForInput(0, sigStr, pubKey) == 0`, `(0, sigStr) == 0`, `(0, badSig) == -1`
  (testMultisig.py:239-256).

### 9.3 USTX ID — pytest/testMultisig.py:211-237

USTXI `(tx1raw, out 1, pubKey)`; DTXOs P2PKH to
`normalizeAddrStr('mhyjJTq9RsDfhNdjTkga1CKhTiL5VFw85J')` 1.00 BTC and
`normalizeAddrStr('mgoCqfR25kZVApAGFK3Tx5CTNcCppmKwfb')` 0.49 BTC (hash160s are
network-independent) → `ustx.lockTime == 0`, `ustx.uniqueIDB58 == 'J2mRenD7'`
(testMultisig.py:223; recomputed ✔). Binary and ASCII round-trips must be byte-identical.

### 9.4 Multisig signing status matrix — pytest/testMultisig.py:328-392

Keys `privKeys = ['\xaa'*32, '\xbb'*32, '\xcc'*32]`; `msScript =
pubkeylist_to_multisig_script(pubs, 2)` must equal the script from the reversed list
(sorted keys). For each subset of signers: `allSigned == (count > 1)`,
`statusM[0] == NO_SIGNATURE if count==0 else ALREADY_SIGNED`,
`statusM[1] == NO_SIGNATURE if count<2 else ALREADY_SIGNED`; USTX `canBroadcast ==
(count > 1)`. Funding tx `signedFundMS` at testMultisig.py:308-321.

### 9.5 Low-S — pytest/testSigning.py:11-22

```python
sbdPrivKey = SecureBinaryData(b'\x01'*32)
for i in range(100):
   msg = "some random msg %s" % random.random()
   sbdSig = CryptoECDSA().SignData(SecureBinaryData(msg), sbdPrivKey, False)
   derSig = createDERSigFromRS(binSig[:32], binSig[32:])
   r, s = getRSFromDERSig(derSig)
   assert binary_to_int(s, BIGENDIAN) <= SECP256K1_ORDER / 2
```

### 9.6 RFC 6979 `getDetKVal` vectors — cppForSwig/gtest/CppBlockUtilsTests.cpp:188-193, 338-349, 423-442

(input = message bytes; `getDetKVal` applies SHA256 itself; all six secp256k1 rows
re-verified in Python 3 against a standard RFC 6979 implementation ✔)

| priv (hex) | message | expected k |
|---|---|---|
| `9d0219792467d7d37b4d43298a7d0c05` | `sample` | `8fa1f95d514760e498f28957b824ee6ec39ed64826ff4fecc2b5739ec45b91cd` |
| `cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50` | `sample` | `2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3` |
| `01` | `Satoshi Nakamoto` | `8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15` |
| `01` | `All those moments will be lost in time, like tears in rain. Time to die...` | `38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3` |
| `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140` | `Satoshi Nakamoto` | `33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90` |
| `f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181` | `Alan Turing` | `525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1` |
| `e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2` | `There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!` | `1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3d` |
| `009A4D6792295A7F730FC3F2B49CBC0F62E862272F` (order `04000000000000000000020108A2E0CC0D99F8A5EF`, 168 bits) | `I want to be larger than the curve's order!!!1!` | `011e31b61d6822c294268786a22abb2de5f415d94f` |

NIST P-curve rows (secp192r1…secp521r1) are at CppBlockUtilsTests.cpp:251-335. For a
*transaction* signature Armory passes `z = hash256(preimage)` as "message" (§3.3).

### 9.7 jasvet — pytest/testJasvet.py

* testHash160ToBC (lines 15-34): h160 `751e76e8199196d454941c45d1b3a323f1433bd6` ↔
  `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` ↔ pubkey
  `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`; h160
  `91b24bf9f5288532960ac687abb035127b1d28a5` ↔ `1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm` ↔
  pubkey `0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8`.
* testB58 (37-43): `00010203` ↔ `1Ldp`.
* testDec (55-62): `decbin(0x7483729483792178)` = `7483729483792178`;
  `decvi(0x7483729483792178)` = `ff7821798394728374`.
* testFormat (64-67): `format_msg_to_sign(b'hello')` =
  `18426974636f696e205369676e6564204d6573736167653a0a0568656c6c6f`.
* testSer (69-74): `EC_KEY(1).pubkey.ser()` = the uncompressed G above → `1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm`.
* testVerify (79-90): `sig = 'G/8M14BRD6GU96y6o1x+9xSfoWBdzZp8p1e/vAZ857D4l9+ozM08CTnzqsxkv1GANssNh1MEmtqgrgEfSPRX5gU='`;
  `digest` = a full clearsign block ("Comment: Signed by Bitcoin Armory v0.92.3", the
  announcement list `changelog/bootstrap/downloads/notify` with SHA256s, CRC line
  `=AnjN`) — `sig` at testJasvet.py:80, `msg` hex at :81, `digest` hex at :82, `formatted` at :84; `FormatText(digest, True) == formatted` (:85);
  `readSigBlock(digest) == (sig, msg)`; `verify_message_Bitcoin(sig, msg) ==
  '1NWvhByxfTXPYNT4zMBmEY3VL8QJQtQoei'` (= `ARMORY_INFO_SIGN_ADDR`, AU:76). All
  recomputed ✔ (header byte 27, uncompressed).
* testSign (93-102): `Signature(1,1).ser()` = `00…01` ‖ `00…01` (64 bytes);
  `sign_message_Bitcoin(b'secretsecretsecretsecretsecretse', b'hello there')` verifies.
* testMisc (104-111): `ASv1B64(b'\x01'*32, b'Hello world!\n')` starts with
  `-----BEGIN BITCOIN MESSAGE-----` and ends with `-----END BITCOIN MESSAGE-----`.
* testI2d (45-52): DER private-key encodings for `EC_KEY(1)` (uncompressed and
  compressed) — not used by Armory signing.

### 9.8 pytest/testUtility.py

* testConversion (lines 10-68): `b'\x01\x02\x03'` ↔ hex `010203` ↔ int 66051 (BE) /
  197121 (LE); padded `int_to_binary(66051, 10, BIGENDIAN) == '\x00'*7 + '\x01\x02\x03'`,
  LE padded = `'\x03\x02\x01' + '\x00'*7`.
* testSigningKey (70-75): `hash160_to_addrStr(hash160(ARMORY_INFO_SIGN_PUBLICKEY), '\x00')
  == ARMORY_INFO_SIGN_ADDR` (`1NWvhByxfTXPYNT4zMBmEY3VL8QJQtQoei`).

### 9.9 pytest/testArmoryEngineUtils.py

VarInt (lines 101-109): `packVarInt(65) == ['A',1]`, `255 → ['\xfd\xff\x00',3]`,
`65536 → ['\xfe\x00\x00\x01\x00',5]`, `10**12 → ['\xff\x00\x10\xa5\xd4\xe8\x00\x00\x00',9]`; inverses.

Amounts (lines 153-168, `LONG_TEST_NUMBER = 98753178900`):

```
coin2str(0, 4)                          == '            0.0000'
coin2str(98753178900, 4)                == '          987.5318'
coin2str(98753178900, 8, False)         == '987.53178900'
coin2str(98753178900, 12, False, 10)    == '987.5317890000'
coin2strNZ(98753178900)                 == '      987.531789  '
coin2strNZS(98753178900)                == '987.531789'
coin2str_approx(98753178900)            == '      988       '
coin2str_approx(-98753178900)           == '     -988       '
str2coin('987.53178900')                == 98753178900
str2coin('    ')                        -> ValueError
str2coin('-1', False)                   -> NegativeValueError
str2coin('-1', True)                    == -100000000
str2coin('-1.1', False)                 -> NegativeValueError
str2coin('.1111', True, 2, False)       -> TooMuchPrecisionError
str2coin('.1111', True, 8, True)        == 11110000
```

`str2coin` rounds to 8 decimals: `(int(lhs + rhs[:9].ljust(9,'0')) + 5) / 10` (AU:1301-1322).

URIs (`testBitcoinUriParser`, lines 257-317):

```
uri1 = "bitcoin:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=0.1&label=Foo%20bar&r=https://example.com/foo/bar/"
  -> {address: 1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW, amount: 10000000, label: "Foo bar", r: "https://example.com/foo/bar/"}
uri2 = "bitcoin:mq7se9wy2egettFxPbmn99cK8v5AFq55Lx?amount=0.11&r=https://merchant.com/pay.php?h%3D2a8628fc2fbe"
  -> {address: mq7se9wy2egettFxPbmn99cK8v5AFq55Lx, amount: 11000000, r: "https://merchant.com/pay.php?h=2a8628fc2fbe"}
uri3 = "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"
  -> {address: 175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W}
uri4 = "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Luke-Jr"
  -> {address: …, label: "Luke-Jr"}
uri5 = "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=20.3&label=Luke-Jr"
  -> {address: …, amount: 2030000000, label: "Luke-Jr"}
uri6 = "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz"
  -> {address: …, amount: 5000000000, label: "Luke-Jr", message: "Donation for project xyz"}
uri7 = "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999"
  -> {address: …, "req-somethingyoudontunderstand": "50", "req-somethingelseyoudontget": "999"}   (parser keeps them; AQ rejects)
uri8 = "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?somethingyoudontunderstand=50&somethingelseyoudontget=999"
  -> {address: …, "somethingyoudontunderstand": "50", "somethingelseyoudontget": "999"}
```

Note `uri2`'s `?` inside the `r=` value is kept by `parse_qs` (only `&`/`;` split).

### 9.10 Derived vectors from this analysis (fixtures, §8)

| Input | Expected |
|---|---|
| unsigned tx of `8gRmZv48` (§8.1) | ID `8gRmZv48` |
| high-S sig `…02210095ced701…2801` | low-S `…02206a3128fe4a1401be40cd5aae16b032d9792526ae3fc9e58db91031b6b58d061901` |
| finalized `8gRmZv48` | txid `347f1b745b3b7fb38bbec2af070f31cc567cedf41693008ae451950d77a3d5d0` |
| testMultisig `7oXWAFds` oversign | txid `7aa88ad8…2cba` (raw in §8.4) |
| `crc24` of the testJasvet signature (65 B) | emitted base64 `AnjN` (LSB-first) |

---

## 10. Not supported (vs. current Bitcoin) — factual, from code

| Feature | Status in 0.93.3 | Evidence |
|---|---|---|
| SegWit inputs (P2WPKH, P2WSH, P2SH-P2WPKH/P2WSH) and BIP143 sighash | **None.** No witness serialization, no marker/flag parsing, legacy sighash only | TX:651-691, TX:857-895 |
| SegWit / Taproot outputs (v0/v1 programs) | Classified `NONSTANDARD`; GUI address entry only accepts Base58Check with `ADDRBYTE`/`P2SHBYTE`, so they cannot be entered as addresses | BTU:884-912, AU:2135-2147 |
| Bech32 / Bech32m addresses | No encoder/decoder anywhere | grep |
| Taproot / Schnorr (BIP340/341) | None | |
| Sighash types other than ALL (NONE, SINGLE, ANYONECANPAY) | Rejected at create (TX:866), verify (TX:1298), wallet sign (WLT:2704), script eval (SC:263) | |
| RBF (BIP125) signaling | Never: every input uses `nSequence = 0xffffffff` (TX:2139, TX:966); a non-max sequence in a USTXI only logs a warning (TX:1010-1012, 1486-1487) | |
| nLockTime | Always 0 from all creation paths (TX:2109, TF, armoryd). `UnsignedTransaction.lockTime` is **never assigned** from the `lockTime` argument (only `pytxObj.lockTime` is, TX:1979) and `serialize()` writes `self.lockTime` (TX:2192) — so a non-zero lockTime would be written as 0 on re-serialization (quirk Q1) | |
| Anti-fee-sniping, CLTV (BIP65), CSV/relative locktime (BIP68/112/113) | None; opcodes 0xb1/0xb2 absent from tables | TX:28-300 |
| PSBT (BIP174/370) | None; own USTX format only (§1) | |
| BIP32/HD derivation paths in signing metadata | `wltLocator` field exists, always empty | TX:912-919 |
| Compressed public keys for wallet keys / signing / USTX verification | Not supported (§2) | TX:1207-1210, EU:453-458, PyBtcAddress.py:172 |
| OP_RETURN outputs | No builder; would be `NONSTANDARD` (allowed with a warning if passed as a raw script) | TX:2122-2126 |
| Fee rate (sat/vB), modern dust rules, `estimatesmartfee` | Fee = `(1+floor(bytes/1000)) * 10000` or Core `estimatefee`; dust = output < 0.01 BTC for "free tx" logic only | CS:727-936 |
| Priority-based free transactions | **Assumed to exist** (removed from Core in 0.12/0.15) — fee can be suggested as 0 | CS:819-825, 926-929 |
| BIP62 strict DER / NULLDUMMY enforcement on verify | Not enforced (Crypto++ accepts high-S; DER parser lenient). Low-S *is* produced. | AU:2995-3020 |
| BIP137/BIP322 message signatures for P2SH/segwit | None; only P2PKH (uncompressed for wallet keys) Bitcoin-Qt style | JV |
| BIP21 extensions (`lightning=`, BIP72 `r=` payment requests) | `r=` is parsed into the dict but ignored; `req-` unknown → refused | AU:2893-2922, AQ:2690-2702 |
| Legacy BIP-0010 TxDP | No longer parsed (§1.10) | |
| Multisig with M,N > 16 or > 3 keys standardness | Script templates only OP_1..OP_16; P2SH lockboxes warn if "non-standard to spend" | BTU:1123-1151, MultiSigUtils.py:227-236 |

---

## 11. Quirks list for the Rust port (decide: replicate, fix, or reject)

| ID | Quirk | Source | Recommendation |
|---|---|---|---|
| Q1 | `UnsignedTransaction.lockTime` is only ever assigned `0` (TX:1957); `createFromUnsignedTxIO` sets only `pytxObj.lockTime` (TX:1979); `serialize()` and `toJSONMap()['locktimeint']` read `self.lockTime` (TX:2192, 2256). The ID is computed from `pytxObj` (with lockTime L) but the body carries 0, so a USTX built with L≠0 (`createFromPyTx` on such a tx, or `createFromUnsignedTxInputSelection(..., lockTime=L)`) fails its own ID check (`UnserializeError`, TX:2236-2240) after one ASCII round-trip | TX:1957, 1979, 2192, 2256 | Fix (carry lockTime); every existing file has 0 so this is compatible |
| Q2 | `UNSIGNED_TX_VERSION` used as Bitcoin `tx.version` (=1); `createFromPyTx` silently rewrites a source tx's version to 1, so a v2 tx cannot be represented | TX:1978, 2108 | Keep tx.version = 1 for ID compatibility; decouple constants |
| Q3 | USTXI/DTXO layouts G0/G1/G2 all `version=1` | §1.9 | Write G2; optionally read G0/G1 with fallback |
| Q4 | `p2shMap` hex-key vs raw-key mismatch → DTXO p2sh empty | TX:2071 vs 2088/2159 | Fix (single key type) |
| Q5 | `readAsciiBlock` ignores BLKSTRING | AU:1339 | Check type in Rust; still accept any width/line ending |
| Q6 | Writer width 64, readers & fixtures 80 | AU:1326 | Write 64 (current) or 80 (fixtures) — both readable by 0.93.3 |
| Q7 | Nonce `h1 = SHA256(z)` | DS, §3.3 | Replicate if byte-identical sigs are needed for tests |
| Q8 | Low-S applied at finalize to stored sigs; stored sigs may be high-S | TX:1148-1160 | Replicate (normalize on finalize) |
| Q9 | `scriptPushData` 76/256/65536 boundary bugs | SC:82-94 | Fix (minimal pushes); identical for all real sizes |
| Q10 | Multisig pubkeys ignored on USTXI unserialize (taken from script) | TX:1056-1063 | Replicate |
| Q11 | Non-standard prevout → `NameError` | TX:1066 | Reject cleanly |
| Q12 | `SingleInput_SingleValue` dead CENT branch; `estimatePriority` inverted; `minFee < 0.0005` | CS:295-296, 752, 610 | Replicate only if selection parity is required; otherwise redesign |
| Q13 | Integer division in `diffPct`, `dPriority`, `prioritySum` | CS:479, 516, 787, 819 | Same |
| Q14 | Random sort methods 8/9 + output shuffle | CS:243-257, TF:732 | Use a CSPRNG for the output shuffle; selection nondeterminism is acceptable |
| Q15 | `calcMinSuggestedFeesNew` omits input bytes | CS:899-905 | Fix |
| Q16 | jasvet CRC24 byte order LSB-first; random k; no low-S; verify returns an address, not bool | JV:555-569, 45-49 | Replicate CRC order for interop with Armory blocks; caller must compare address |
| Q17 | `TxInExtractPreImageIfAvail` always `''` | TX:443 | Fix |
| Q18 | `addrStr_to_scrAddr` constructs but doesn't raise `BadAddressError` | AU:1593, 1601 | Fix (raise) |
| Q19 | `getRSFromDERSig` lenient; tolerates trailing hashtype | AU:2995-3020 | Parse strictly on input from others but accept what Armory produced |
