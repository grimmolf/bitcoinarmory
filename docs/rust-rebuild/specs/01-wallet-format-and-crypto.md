# Spec 01 — Armory legacy wallet file format (v1.35) and wallet cryptography

Status: implementation spec for the Rust rewrite. Target: read (and, if desired, write)
existing Armory `.wallet` files **bit-for-bit**, and reproduce the legacy (pre-BIP32)
Armory deterministic key chain, KDF and private-key encryption exactly.

Primary sources (all paths relative to repo root):

| Short name | File |
|---|---|
| `PBW` | `armoryengine/PyBtcWallet.py` |
| `PBA` | `armoryengine/PyBtcAddress.py` |
| `AU`  | `armoryengine/ArmoryUtils.py` |
| `BP` / `BU` | `armoryengine/BinaryPacker.py` / `armoryengine/BinaryUnpacker.py` |
| `EUh` / `EUc` | `cppForSwig/EncryptionUtils.h` / `cppForSwig/EncryptionUtils.cpp` |
| `BUh` | `cppForSwig/BtcUtils.h` |
| `SWIG` | `cppForSwig/CppBlockUtils.i` |

Citations are `FILE:line`. "Fixture" = the TIAB golden wallets from `pytest/tiab.zip`
(`armory/armory_{GDHFnMQ2,vzgEfJrJ,DZMmtb2v}_.wallet` and their `_backup` twins).

---

## 0. Verification status (read this first)

Three independent checks were made while writing this spec:

1. **Fixture parse** — a Python 3 re-implementation of this spec (parser, checksum
   verifier, secp256k1, chain derivation) was run against all three TIAB wallets.
2. **Real C++ harness** — Armory's own `cppForSwig/EncryptionUtils.cpp`,
   `BinaryData.cpp`, `UniversalTimer.cpp` were compiled (unmodified, read-only) together
   with Armory's bundled Crypto++ (`cppForSwig/cryptopp`) into a small harness, and
   used to generate/confirm KDF, AES-CFB and chain vectors.
3. **Repo unit-test constants** — literal vectors from `pytest/*.py` were reproduced.

| Area | How verified |
|---|---|
| Header layout & every offset (§2), file magic, version int, network magic, unique-ID bytes & Base58 form, create date, labels, highest-used, KDF block layout + checksum, crypto block = zeros, root-address offset 846, 1024-byte reserved block, entry stream starts at 2107 | **Fixture-verified** (all 3 wallets) |
| 237-byte address record: every field offset, all five checksums, flag bit order (LSB-first), empty-field encoding (`5df6e0e2`), `chainIndex`/`depth` INT64, time/block ranges | **Fixture-verified** (root + 50 key entries) |
| Entry stream: type 0x00 key entries, type 0x01 address comments, type 0x02 tx comments (tx hash stored in internal/LE byte order) | **Fixture-verified** |
| Chain derivation (private and public) for every chained address; chaincode = Armory-HMAC(hash256(rootPriv)) | **Fixture-verified** (root chaincodes of all 3 wallets match the non-standard HMAC, NOT standard HMAC-SHA256) |
| Wallet ID = base58(reverse(ADDRBYTE ‖ first160[:5])) | **Fixture-verified** + `testPyBtcWallet.py` ID `3VB8XSoY` |
| P2PKH address strings, WIF private keys from `testArmoryDTiab.py` match keys stored in fixture | **Fixture-verified** |
| `highestUsed`+1 → expected next address `muEePRR9…` | **Fixture-verified** |
| KdfRomix | **Verified by linking real `EncryptionUtils.cpp`**; Python port matches it byte-for-byte |
| AES-256-CFB | `testPyBtcAddress.py` constants + NIST vectors from `old_not_very_good_tests.cpp` + real C++ |
| ComputeChainedPrivateKey / PublicKey | `testPyBtcAddress.py` constants + real C++ + fixtures |
| **Encrypted** address entries, **pending** (`createPrivKeyNextUnlock`) entries, **imported** (`chainIndex=-2`) entries, **deleted** (type 0x04) entries, **watching-only** files, PKCC text files, the update-flag files | **Code-derived only — no fixture contains them.** The fixtures are all unencrypted (header flags = 0; `testArmoryDTiab.py:442` "Wallets in the TIAB start out unencrypted"). |

---

## 1. Primitives and conventions

### 1.1 Endianness and integer packing
* `BinaryPacker.put`/`BinaryUnpacker.get` default to **little-endian** for every integer
  type (`BP:39`, `BU:54`). `UINT8/16/32/64` are unsigned, `INT64` is signed two's complement
  (`struct '<q'`).
* `BINARY_CHUNK` with `width=w` right-pads with `0x00` to `w` bytes and raises if the
  data is longer than `w` (`BP:63-70`).
* Byte strings for keys/hashes are stored "as is": private keys and pubkey X/Y are
  **big-endian** 32-byte integers (`EUc:483-503`); hash160 / tx hashes are raw digest bytes.

### 1.2 Hashes
* `sha256`, `sha512`: standard (`AU:1805-1810`).
* `hash256(x) = sha256(sha256(x))` (`AU:1815`; C++ `BtcUtils::getHash256` `BUh:486-520`;
  `SecureBinaryData::getHash256` `EUh:186`).
* `hash160(x) = ripemd160(sha256(x))` (`AU:1818` → C++ `BUh:554-566`).
* `hash256(b"") = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456`;
  its first 4 bytes `5df6e0e2` are the checksum of every **empty** field (see §1.5).

### 1.3 Base58
Alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` (`AU:137`).
Encode: count leading `0x00` bytes → that many `'1'`; big-endian bigint → base58 digits
(`AU:1997-2024`). Decode is the inverse; unknown char raises (`AU:2027-2059`). No
checksum is added by these functions; callers append `hash256(...)[:4]` themselves.

### 1.4 Version integers
`getVersionInt((a,b,c,d)) = a*10^7 + b*10^5 + c*10^3 + d` (`AU:354-361`).
`PYBTCWALLET_VERSION = (1,35,0,0)` → **13500000 = 0x00CDFE60** (`AU:70`); on disk
`60 fe cd 00`. `readVersionInt` splits the zero-padded 10-digit decimal string
(`AU:369-376`). Fixture: all three headers and every address record carry 13500000.

### 1.5 Checksums (`computeChecksum`, `verifyChecksum`, `fixChecksumError`)
* `computeChecksum(data, n=4) = hash256(data)[:n]` (`AU:2319-2320`). The wallet file uses
  n=4 everywhere; PKCC/EasyType16 lines use n=2.
* **Empty field rule**: a field that is logically empty is written as `width` zero bytes
  followed by `hash256(b"")[:4] = 5df6e0e2` (`PBA:928-938` writes `chk('')`). On read,
  `chkzero()` maps an all-zero field to `b""` **before** verification (`PBA:1003-1011`,
  `PBA:1040,1052,1054,1079`) so `hash256(b"")` matches. *Fixture: root IV of all three
  wallets is 16×00 + `5df6e0e2`.* Consequence: a field whose real value is all zeros
  cannot be represented (it would be read back as empty).
* `verifyChecksum(data, chk)` — port **exactly** (`AU:2323-2375`), returns the (possibly
  corrected) data or `b""` on failure:
  ```
  fn verify_checksum(data, chk) -> bytes:
      if hash256(data).starts_with(chk):           return data            # ok
      if hash256(reverse(data)).starts_with(chk):  return reverse(data)   # "reversed endianness" accepted!
      # fixChecksumError: try every single-byte substitution, byte 0 first, value 0..255 ascending
      for i in 0..len(data):
          for v in 0..=255:
              d2 = data with d2[i] = v
              if hash256(d2).starts_with(chk): return d2                  # first hit wins
      if chk == 5df6e0e2: return b""                                    # "was originally empty"
      # checksum itself corrupted? (single byte of chk wrong)
      h = hash256(data)
      for i in 0..len(chk): for v in 0..=255:
          c2 = chk with c2[i]=v
          if h.starts_with(c2): return data
      return b""                                                        # unrecoverable
  ```
  Note `fixChecksumError` (`AU:2303-2316`) iterates `val` from 0 and returns the first
  match; the candidate with `val == original byte` is also tried (it simply fails since
  the unmodified hash already failed). Test vectors in §14.4.
* There is **no** checksum on: the header fields other than the KDF block, labels,
  `highestUsed`, flags, version, chainIndex, depth, time/block ranges, comments.

### 1.6 Network constants
| | Mainnet | Testnet3 |
|---|---|---|
| `MAGIC_BYTES` (header off 12) | `f9 be b4 d9` (`AU:474`) | `0b 11 09 07` (`AU:491`) |
| `ADDRBYTE` (P2PKH) | `0x00` (`AU:479`) | `0x6f` (`AU:496`) |
| `P2SHBYTE` | `0x05` | `0xc4` |
| `PRIVKEYBYTE` (WIF) | `0x80` (`AU:481`) | `0xef` (`AU:498`) |
| default keypool | `--keypool` default **100** (`AU:110`, `PBW:204`) | hard-coded **10** (`PBW:202`) |

Known magic → name table `AU:329-332` (also `fa bf b5 da` "Old Test Network").

---

## 2. File header (fixed 2107 bytes)

Written by `packHeader` (`PBW:1908-1956`), read by `unpackHeader` (`PBW:1961-2038`).
All offsets are absolute file offsets. **Fixture-verified.**

| Off | Size | Type | Field | Notes |
|---:|---:|---|---|---|
| 0 | 8 | bytes | fileID | `ba 57 41 4c 4c 45 54 00` = `"\xbaWALLET\x00"` (`PBW:182`). Wallet discovery also requires this (`AU:1035-1040`). |
| 8 | 4 | u32 LE | version | `getVersionInt(PYBTCWALLET_VERSION)` = 13500000 (`PBW:1915`) |
| 12 | 4 | bytes | magic | network magic (`PBW:1916`) |
| 16 | 8 | u64 LE | wallet flags | see §2.1 (`PBW:1874-1881`) |
| 24 | 6 | bytes | uniqueIDBin | see §2.2 (`PBW:1923`) |
| 30 | 8 | u64 LE | createDate | unix seconds, `long(time.time())` at creation (`PBW:872,1926`) |
| 38 | 32 | bytes | labelName | "short label / wallet name", zero-padded, **not necessarily NUL-terminated** (`PBW:1930`) |
| 70 | 256 | bytes | labelDescr | long description, zero-padded (`PBW:1934`) |
| 326 | 8 | i64 LE | highestUsedChainIndex | `-1` (`ff…ff`) for a fresh wallet (`PBW:871,1938`) |
| 334 | 256 | block | KDF parameters | §2.3 (`PBW:1942`) |
| 590 | 256 | block | crypto parameters | always written as 256×`00` (`PBW:1488-1494`); **read and ignored** (`PBW:1497-1509`) |
| 846 | 237 | record | root address | 237-byte `PyBtcAddress` record (§3), `chainIndex=-1` (`PBW:1949-1951`) |
| 1083 | 1024 | bytes | reserved | written as zeros (`PBW:1954`); reader just skips 1024 (`PBW:2031`) |
| 2107 | … | stream | entries | §4 |

Offsets remembered by the Python object for in-place updates (`PBW:238-244`):
`offsetWltFlags=16, offsetLabelName=38, offsetLabelDescr=70, offsetTopUsed=326,
offsetKdfParams=334, offsetCrypto=590, offsetRootAddr=846`.

### 2.1 Wallet flags (u64 at offset 16)
`flags` is built as a 64-element list and converted by `bitset_to_int`, where list
element *i* is **bit i (value 2^i)** — LSB first (`AU:1974-1989`, `PBW:1874-1881`).

| Bit (mask) | Meaning | Source |
|---|---|---|
| 0 (`0x01`) | `useEncryption` — private keys are AES-encrypted | `PBW:1877,1902` |
| 1 (`0x02`) | `watchingOnly` | `PBW:1878,1903` |
| 2 (`0x04`) | multisig wallet → reader raises `isMSWallet('Cannot Open MS Wallets')` | `PBW:1904-1905` |
| 3..63 | unused; never written; dropped on any flags rewrite | |

Fixture: all three = `0`. "Offline" vs "Watching-only" (GUI) is **not** in the file; it is a
per-wallet `IsMine` setting in the settings file (`qtdefines.py:245-250`).

### 2.2 Unique ID (wallet ID)
```
first160    = hash160(pubkey65 of chain index 0)       # the FIRST CHAINED address, not the root
uniqueIDBin = reverse(ADDRBYTE || first160[0:5])       # 6 bytes: first160[4],[3],[2],[1],[0],ADDRBYTE
uniqueIDB58 = base58(uniqueIDBin)                       # no checksum appended
```
(`PBW:865-866`, also `PBW:624,713`, `PBA:24-29`). The last byte of `uniqueIDBin` is
the network byte; reader rejects a mismatch (§2.4). The ID depends on root key **and**
chaincode ("new in 1.35", `PBW:861-864`). Default file name: `armory_<ID>_.wallet`
(`PBW:61-62`). Fixture: `1e8c24739e6f`→`GDHFnMQ2`, `6c6dcbf1d26f`→`vzgEfJrJ`,
`1937d8544a6f`→`DZMmtb2v`, each equal to the recomputed value.

### 2.3 KDF parameter block (256 bytes at offset 334)
`serializeKdfParams` (`PBW:1423-1448`) / `unserializeKdfParams` (`PBW:1452-1484`):

| Rel off | Size | Type | Field |
|---:|---:|---|---|
| 0 | 8 | u64 LE | memoryReqtBytes |
| 8 | 4 | u32 LE | numIterations |
| 12 | 32 | bytes | salt |
| 44 | 4 | bytes | `hash256(bytes[0:44])[:4]` |
| 48 | 208 | zeros | padding (not checked on read) |

* No KDF (wallet never had encryption configured): the whole 256 bytes are zero; reader
  tests `bytes[0:44] == 44×00` → `kdf = None` (`PBW:1466-1467`).
* Corrupt-but-fixable (single byte, §1.5) → only the corrected **44 data bytes** are
  written back at offset 334 (`PBW:1469-1476`), not the checksum; a corrupted checksum
  byte (for which `verifyChecksum` returns the data unchanged) is tolerated and left on
  disk forever (unlike address records, which are fully re-serialised, §3.3).
  Unfixable → `UnserializeError`.
* `mem` is u64 on disk but `KdfRomix` takes `uint32_t` (`EUh:231`); values ≥2^32 cannot
  occur in valid files.
* **The KDF block survives decryption**: `changeWalletEncryption(None)` never clears it.
  All three fixtures have header flag 0 but a populated KDF block, e.g. GDHFnMQ2:
  mem=2097152, iter=2, salt=`1ee82e6ef29655e597da9954b64aab87b470126c7b28b76d3d41168946305ffe`;
  vzgEfJrJ: 2097152, 2, `2c40505fc3e960d5a3ccb3c2c6fefae2e39d7f47073e2c7e56f31122e6681357`;
  DZMmtb2v: 4194304, 2, `f6de5e296a2f4628045e68da14e92aec4713ded6d58166ffdd7591c6298f9f62`.
  ⇒ **Use header flag bit 0, never "KDF present", to decide whether keys are encrypted.**

### 2.4 Header read algorithm and quirks
`unpackHeader` (`PBW:1961-2038`):
1. Read fileID (not validated here; only discovery checks it), version, magic, flags
   (MS flag raises).
2. Read uniqueIDBin, B58-encode, read createDate.
3. If `magic != MAGIC_BYTES` → log, `return -1`; if `uniqueIDBin[5] != ADDRBYTE` → `return -2`
   (`PBW:1982-1990`). **Bug:** `readWalletFile` ignores the return value (`PBW:2086`)
   and keeps parsing the entry stream from offset 38 (garbage). A Rust reader should
   hard-fail instead.
4. Labels: `bytes.strip(b'\x00')` — strips NULs at **both ends** (`PBW:1994,1999`).
   Labels are raw bytes (in practice ASCII/UTF-8). A 32-byte label has no terminator
   (fixture vzgEfJrJ: `"Secondary Wallet with a really r"` fills all 32 bytes and the
   description fills all 256).
5. highestUsed (i64), KDF block (§2.3), crypto block (256 bytes skipped, non-zero
   tolerated), root record (237 bytes, §3); if re-serialising the parsed root differs from
   the raw bytes, the normalised bytes are written back (`PBW:2018-2024`). If
   `useEncryption`, root (and wallet) marked locked (`PBW:2026-2028`).
6. Skip 1024 reserved bytes.
7. After the entry stream: if `version < 13500000` → `LOGERROR('Wallets older than version
   1.35 no longer supported!')` and `readWalletFile` returns `None` (`PBW:2137-2140`).

Label writers: `createNewWallet` truncates `[:32]`/`[:256]` (`PBW:867-868`);
`setWalletLabels` (`PBW:1861-1871`) pads with `ljust` and **does not truncate** (callers
truncate, `qtdialogs.py:1977-1978`); an over-long label would overwrite the next field.

---

## 3. The 237-byte address record (`PyBtcAddress.serialize`)

Serialize `PBA:871-985`, unserialize `PBA:988-1103`. Size 237 is computed at runtime
(`PBW:231`). Offsets are relative to the record start (root: file offset 846; key entries:
entry offset + 21). **Fixture-verified.**

| Rel off | Size | Type | Field | Checksum covers |
|---:|---:|---|---|---|
| 0 | 20 | bytes | addr160 = hash160(pubkey65) | — |
| 20 | 4 | bytes | chk(addr160) | addr160 |
| 24 | 4 | u32 LE | version = 13500000 (always the *current* version on write, `PBA:949`) | — |
| 28 | 8 | u64 LE | address flags (§3.1) | — |
| 36 | 32 | bytes | chaincode | — |
| 68 | 4 | bytes | chk(chaincode) | chaincode |
| 72 | 8 | i64 LE | chainIndex (`-1` root, `0..` chained, `-2` imported) | — |
| 80 | 8 | i64 LE | chainDepth (`createPrivKeyNextUnlock_ChainDepth`) | — |
| 88 | 16 | bytes | IV | — |
| 104 | 4 | bytes | chk(IV) | IV |
| 108 | 32 | bytes | private key (plain or AES-CFB ciphertext) | — |
| 140 | 4 | bytes | chk(privkey bytes as stored) | privkey |
| 144 | 65 | bytes | public key `04‖X‖Y` (uncompressed) | — |
| 209 | 4 | bytes | chk(pubkey) | pubkey |
| 213 | 8 | u64 LE | firstSeen time (`timeRange[0]`, init `2^32-1`) | — |
| 221 | 8 | u64 LE | lastSeen time (`timeRange[1]`, init `0`) | — |
| 229 | 4 | u32 LE | firstSeen block (`blkRange[0]`, init `2^32-1`) | — |
| 233 | 4 | u32 LE | lastSeen block (`blkRange[1]`, init `0`) | — |

Every checksum is `hash256(field)[:4]` of the **logical** value; an empty value is written
as zeros + `5df6e0e2` (§1.5). The checksum of the private key slot is over whatever is
stored there (ciphertext when encrypted). Time/block ranges are informational (updated by
`touch()`, `PBA:178-211`) and not used for any crypto.

### 3.1 Address flags (u64 at rel. offset 28), LSB-first like §2.1
| Bit (mask) | Name | Value written (`PBA:921-926`) |
|---|---|---|
| 0 (`0x01`) | containsPrivKey | `hasPrivKey()` = encr≠∅ or plain≠∅ or `createPrivKeyNextUnlock` (`PBA:120-130`) |
| 1 (`0x02`) | containsPubKey | pubkey≠∅ |
| 2 (`0x04`) | useEncryption | `serializeWithEncryption` (see below) |
| 3 (`0x08`) | createPrivKeyNextUnlock ("pending") | |

Fixture: every record has flags `0x03` (unencrypted, priv+pub).

`serializeWithEncryption = useEncryption`, **except** when `useEncryption` is set but the
encrypted key is empty while a plaintext key exists — then the plaintext key is written
and bit 2 is cleared (logged warning) (`PBA:906-917`).

### 3.2 What goes in the IV / private-key slots
(`PBA:958-975`)

| State | bit2 | bit3 | IV slot (88) | Priv slot (108) |
|---|:-:|:-:|---|---|
| Unencrypted, has priv | 0 | 0 | `binInitVect16` (may be **non-empty**, see note) | plaintext priv (32 B BE) |
| Encrypted | 1 | 0 | this address's IV | `AES256-CFB(kdfKey, IV, plainPriv)` |
| Pending (created while locked) | 1 | 1 | **ancestor's IV** (`createPrivKeyNextUnlock_IVandKey[0]`) | **ancestor's encrypted priv** (`…IVandKey[1]`) |
| No priv (watch-only / pubkey-only / hash-only) | 0 | 0 | whatever `binInitVect16` holds (normally empty) | empty |

Notes:
* Chained addresses always receive a fresh random IV in `extendAddressChain` even when the
  wallet is unencrypted (`PBA:791-792,813-814` → `createFromPlainKeyData(..., IV16=newIV)`
  → `PBA:385-387`). Decrypting a wallet clears IVs (`PBA:663-667`). Fixture: GDHFnMQ2
  idx 18–20 and vzgEfJrJ idx 14 are unencrypted yet carry 16-byte IVs; older addresses
  carry none (presumably encrypted and later decrypted, which clears IVs). **Never infer encryption from IV
  presence; use flag bit 2 (and header bit 0).**
* `chainDepth` (rel 80): initialised to `-1` (`PBA:112`); set to N≥1 for pending
  addresses; set to `0` after a pending address is materialised on unlock (`PBA:601`).
  Fixtures show `-1` and `0` on unencrypted, non-pending records (e.g. GDHFnMQ2 idx 10,11,
  16,17 have depth 0 = "was pending once, since resolved"). Only meaningful when bit 3 set.
* Root record: `chainIndex = -1`, chaincode = wallet chaincode (`PBA:751-757`).
* Imported record: `chainIndex = -2`, chaincode = 32×`ff` with its checksum
  (`PBW:2535-2536`).

### 3.3 Unserialize algorithm (port exactly) (`PBA:988-1103`)
```
addr160  = rec[0:20]                        # NOT chkzero'd
addr160  = verify_checksum(addr160, rec[20:24])
ver      = u32(rec[24:28])                  # ignored
flags    = u64(rec[28:36]); P = bit0; K = bit1; E = bit2; N = bit3
addrChkError = (addr160 == b"")
if addrChkError and not P and not K: raise UnserializeError
chaincode = verify_checksum(chkzero(rec[36:68]), rec[68:72])
chainIndex = i64(rec[72:80]); depth = i64(rec[80:88])
iv   = verify_checksum(chkzero(rec[88:104]),  rec[104:108])
priv = verify_checksum(chkzero(rec[108:140]), rec[140:144])
if P:
    if priv == b"": raise UnserializeError("Checksum mismatch in PrivateKey")
    if E:
        if iv == b"": raise UnserializeError("Checksum mismatch in IV")
        if N: pendingIV, pendingEncKey = iv, priv          # NOT this address's own key
        else: IV, encPriv = iv, priv
    else:
        IV, plainPriv = iv, priv
# if not P: iv and priv are discarded (re-serialisation writes empties)
pub = verify_checksum(chkzero(rec[144:209]), rec[209:213])
if K and len(pub) != 65:
    if len(plainPriv)==32: pub = ComputePublicKey(plainPriv)   # see BUG below
    else: raise UnserializeError("Checksum mismatch in PublicKey")
if addrChkError: addr160 = hash160(pub)
timeRange = (u64(rec[213:221]), u64(rec[221:229])); blkRange = (u32(rec[229:233]), u32(rec[233:237]))
```
**BUG** `PBA:1086` calls `CryptoAES().ComputePublicKey`, which does not exist
(`EUh:279-303`) → Python `AttributeError`. Intent is clearly `CryptoECDSA().ComputePublicKey`;
implement the intent.

Readers (`readWalletFile`, `unpackHeader`) re-serialise every parsed record and, if the
bytes differ from the raw record, write the normalised record back in place
(`PBW:2103-2108`, `PBW:2018-2024`). This is how single-byte errors get repaired, but it also
"normalises" legitimately-different bytes (e.g. the version field, IV/priv bytes on a
record without bit 0). A read-only Rust reader may skip the write-back.

---

## 4. Entry stream (from offset 2107 to EOF)

Read loop `PBW:2086-2133`, entry decoder `unpackNextEntry` `PBW:2041-2063`, writer
`walletFileSafeUpdate` `PBW:2224-2251`, `writeFreshWalletFile` `PBW:1152-1171`.
The class docstring's "4-byte type code" (`PBW:137-154`) is **wrong**: the type is **1 byte**.

| Type byte | Constant | Layout after the type byte | Total size |
|---|---|---|---|
| `0x00` | `WLT_DATATYPE_KEYDATA` | `addr160[20]` ‖ `address record[237]` | 258 |
| `0x01` | `WLT_DATATYPE_ADDRCOMMENT` | `addr160[20]` ‖ `len:u16 LE` ‖ `comment[len]` | 23+len |
| `0x02` | `WLT_DATATYPE_TXCOMMENT` | `txHash[32]` ‖ `len:u16 LE` ‖ `comment[len]` | 35+len |
| `0x03` | `WLT_DATATYPE_OPEVAL` | — reader raises `NotImplementedError`; writer refuses | — |
| `0x04` | `WLT_DATATYPE_DELETED` | `len:u16 LE` ‖ `len` bytes (zeros) | 3+len |
| other | — | **nothing consumed**: the loop simply moves on to the next byte (quirk) | 1 |

(`PBW:30-34`.)

* Key entry: the 20-byte prefix is the dict key; the record's own `addr160` should equal
  it. `walletByteLoc` of the record = entry offset + 21 (`PBW:2102`). Fixture: entries at
  2107, 2365, 2623, … (stride 258).
* Comment entries: no checksum. `MAX_COMMENT_LENGTH = 144` (`AU:177`) is a GUI limit
  only; the format allows 65535. Bodies are opaque bytes (UI writes ASCII/UTF-8).
  `[[ … ]]` comments are "hidden" automatic labels (e.g. `[[ Change received ]]`,
  `PBW:1821,1836,1851`). Tx-comment hashes are the raw (internal, little-endian) tx hash:
  fixture GDHFnMQ2 stores `721507bc…cb421811`, whose display form is
  `111842cb…bc071572` (`testArmoryDTiab.py:65`).
* **Comment overwrite** (`setComment`, `PBW:1766-1796`): if a comment for that hash already
  exists, its **body bytes** (at `loc + 1 + len(hash) + 2`) are overwritten with zeros in
  place (type, hash and length untouched) and a brand-new entry is appended. Type `0x04`
  is NOT used for comments. Reader consequence: the same hash may appear several times;
  entries are applied in file order so the **last one wins**; earlier ones read as
  `len` NUL bytes.
* **Deleted entry** (`deleteImportedAddress`, `PBW:2400-2437`): only imported
  (`chainIndex == -2`) keys can be deleted. The 258-byte key entry is overwritten in place
  with `04` ‖ `ff 00` (u16 255 = 20+237−2) ‖ 255×`00` — same total size.
* Order: entries are appended in creation order (`computeNextAddress` → append,
  `PBW:978-981`), so normal wallets have ascending chain indices. **Files written by
  `writeFreshWalletFile` (fork/copy) emit key entries in Python-2 dict order (arbitrary)
  followed by all comments** (`PBW:1158-1169`). Never rely on order; key by chainIndex.
* Reader state built from the stream (`PBW:2088-2128`):
  `lastComputedChainIndex = max(chainIndex)` over key entries (initial `-UINT32_MAX`),
  `chainIndexMap[chainIndex] = addr160`, `linearAddr160List` in file order;
  `chainIndex < -2` is clamped to `-2` and sets `hasNegativeImports` (`PBW:2118-2120`).
  Records with bit 2 set are marked locked.

---

## 5. Key-derivation function: `KdfRomix`

C++ `EUc:92-290`, header `EUh:217-274`. Python wrapper: `PBW:1423-1616`.
**Verified by compiling the real C++** (vectors in §14.2).

Constants: hash = SHA-512, `HSZ = 64`, output length `kdfOutputBytes = 32` (`EUc:92-109`).

```
fn kdf_romix_one_iter(password: &[u8], salt: &[u8;32], mem: u32) -> [u8;32]:
    seq   = mem / 64                                   # sequenceCount_, EUc:191
    lut   = vec![0u8; mem]
    lut[0..64] = sha512(password || salt)              # EUc:217,228
    nb = 0
    while nb < mem - 64:                               # EUc:234 (u32 arithmetic)
        lut[nb+64 .. nb+128] = sha512(lut[nb .. nb+64])
        nb += 64
    X = lut[mem-64 .. mem]                             # last 64-byte slot, EUc:244
    for _ in 0 .. seq/2:                               # nLookups = seq/2, EUc:261
        idx = u32_le(X[60..64]) % seq                  # native (x86 = LE) read, EUc:265
        V   = lut[64*idx .. 64*idx+64]
        X   = sha512(X xor V)                          # EUc:271-275
    return X[0..32]                                    # EUc:279

fn kdf_romix(passphrase, mem, nIter, salt) -> bytes:
    k = passphrase                                     # EUc:285
    repeat nIter times: k = kdf_romix_one_iter(k, salt, mem)   # 2nd+ iterations hash the 32-byte output
    return k
```
* The passphrase is the raw bytes of the Python `str` given to `SecureBinaryData(...)`
  (GUI: `str(QLineEdit.text())`, i.e. ASCII/Latin-1 in practice). No normalisation.
* Quirk: `nIter == 0` returns the passphrase unchanged (verified: `'abcde'` → `6162636465`),
  which would then be an invalid AES key length. Never produced by calibration (min 1).
* `mem` must be a multiple of 64 and ≥128 for the loop to be well-defined; calibration only
  produces powers of two ≥ 1024.
* Memory/time: 32 MiB max → 524288 slots; the lookup phase is half that.

### 5.1 Parameter calibration (`computeKdfParams`, `EUc:112-181`)
Non-deterministic (timing based); only the stored `(mem, nIter, salt)` matter for
compatibility. For a writer that wants Armory-like parameters:
```
salt = random 32 bytes
if targetSec == 0: nIter = 1; mem = 1024; return
mem = 1024; t = 0
while t <= targetSec/4 and mem < maxMem:   mem *= 2; t = time(one_iter(testKey, mem)); testKey = result
  # testKey starts as "This is an example key to test KDF iteration speed" and is chained
numTest = 1; tAll = 0
while tAll < 0.02: numTest *= 2; tAll = time(numTest × one_iter("This is an example key…"))
nIter = max(1, floor(targetSec / (tAll/numTest + 0.0005)))
```
Python defaults: `targetSec = 0.25`, `maxMem = 32 MiB` (`PBW:36-37`, `PBW:1540-1557`).
`makeEncryptedWalletCopy` uses `computeSystemSpecificKdfParams(0.25)` (`PBW:1220`).

---

## 6. Private-key encryption

### 6.1 Cipher
`CryptoAES::EncryptCFB/DecryptCFB` (`EUc:298-362`): Crypto++ `CFB_Mode<AES>` with the
default feedback size = block size → **AES-CFB128**, key = the 32-byte KDF output →
**AES-256**, IV = 16 bytes, **no padding** (32-byte plaintext → 32-byte ciphertext).
Empty input returns empty. If `EncryptCFB` receives an empty IV it generates a random one
(`EUc:318-319`) — the wallet code never relies on this. CBC variants exist but are unused
by the wallet.

### 6.2 Per-address IVs
Each address record has its own 16-byte IV (rel. offset 88). Sources of IVs:
`SecureBinaryData().GenerateRandom(16)` (Crypto++ `AutoSeededX917RNG<AES>`, `EUh:118`,
`EUc:75-89`) in `extendAddressChain` (`PBA:791-792,850-852`), `enableKeyEncryption(…,
generateIVIfNecessary=True)` (`PBA:328-338`), `lock(generateIVIfNecessary=True)`
(`PBA:536-541`). `createNewWallet(IV=…)` lets a caller fix the root IV (tests use 0x77×16).
Changing the passphrase **keeps existing IVs** (`PBA:658-661`).

### 6.3 Passphrase verification and unlock
* `kdfKey = KdfRomix(mem,nIter,salt).DeriveKey(passphrase)` (`PBW:1521`, `PBW:2782`).
* Verification is done on the **root** record only (`PBW:1512-1536`):
  `PBA:260-292`: `d = AES-CFB-decrypt(kdfKey, rootIV, rootEncPriv)`; locked case:
  `ComputePublicKey(d) == stored pubkey65` (or `hash160(...) == addr160` if no pubkey).
  Returns `False` if the root is not encrypted or has no private key.
* Wallet `unlock` (`PBW:2764-2836`): verify, store `kdfKey`, set
  `lockWalletAtTime = now + (tempKeyLifetime or defaultKeyLifetime=10 s)` (`PBW:216`),
  then iterate **all records sorted by chainIndex** (imported −2, root −1, 0, 1, …) and
  `addr.unlock(kdfKey)`; pending records are resolved and rewritten (§6.5).
* Address `unlock` (`PBA:565-638`): non-pending: `plain = AES-CFB-decrypt(kdfKey, IV,
  encPriv)`; then if no pubkey → compute it, else require `CheckPubPrivKeyMatch` (raises
  `KeyDataError` on mismatch).
* `lock` (`PBA:520-562`, `PBW:2841-2896`): if encrypted copy exists and key unchanged, just
  wipe plaintext; otherwise encrypt with `kdfKey` (error `WalletLockError` if none).
  Locking is enforced only by the application (`checkWalletLockTimeout`, `PBW:528-537`).

### 6.4 Encrypt / decrypt / re-key a wallet
`changeWalletEncryption(secureKdfOutput|securePassphrase|None)` (`PBW:1618-1724`):
* requires the KDF block to be set when enabling encryption (`PBW:1660-1661`); set it with
  `changeKdfParams` (`PBW:1570-1615`), which writes 256 bytes at offset 334.
* For every record: `enableKeyEncryption(generateIVIfNecessary=True)` then
  `changeEncryptionKey(old,new)` (`PBA:641-680`) — new=None clears IV, encPriv and
  `useEncryption`.
* All rewritten records + (if the on/off state changes) the new header flags u64 at
  offset 16 are written in **one** `walletFileSafeUpdate` call (`PBW:1683-1702`).
* `changeKdfParams` on an encrypted wallet re-encrypts with the new KDF in the same atomic
  update (`PBW:1605-1613`).

### 6.5 Pending keys (`createPrivKeyNextUnlock`) — chained while locked
When a new address is chained from a locked, encrypted parent without the key
(`PBA:765-868`, branch `PBA:829-868`):
* The new public key is computed with `ComputeChainedPublicKey` (§7.3).
* Record: bits P,K,E,N = 1,1,1,1; own random IV stored in memory only (not serialised);
  IV/priv slots hold the **nearest materialised ancestor's IV and encrypted private key**;
  `chainDepth` = number of chain steps from that ancestor (parent pending → copy parent's
  pair and `depth+1`, else parent's own pair and `depth=1`).
* Resolution on wallet unlock (`PBW:2811-2835` + `PBA:575-600`), in chainIndex order:
  if the record is pending **and** a previously processed *chained* record exists
  (`addrObjPrev` is only ever assigned records with `chainIndex > -1`, so imported −2 and
  root −1 never qualify) and `depth' = idx − prevIdx > 0`, replace the stored pair with the
  previous record's `(IV, encPriv)` and depth with `depth'` ("n2 unlock fix"). Then:
  `plain = AES-CFB-decrypt(kdfKey, pairIV, pairEnc)`; repeat `depth` times
  `plain = ComputeChainedPrivateKey(plain, chaincode)` (pubkey recomputed internally);
  clear pending, set depth=0, `lock(generateIVIfNecessary=True)` — this encrypts with the
  record's *own* in-memory IV: the random IV assigned at creation if the object was never
  reloaded, otherwise (after a file read, where unserialise leaves it empty) a **fresh
  random IV** — never the stored pair's IV; then unlock, and the wallet rewrites the record (`PBW:2831-2835`). Consequently a pending index-0 record
  always keeps its stored (root-derived) pair.

### 6.6 Watching-only
Header bit 1 set, header bit 0 clear, KDF block zero; every record has bit 0 clear, empty
IV/priv slots (§9). The chain can still be extended from public keys (§7.3).

---

## 7. Deterministic key chain (legacy Armory 1.35, not BIP32)

### 7.1 Root key and chaincode
* Root private key: 32 random bytes (`GenerateRandom(32, extraEntropy)`, `PBW:829-833`).
  Not range-checked against the curve order.
* Chaincode (wallets ≥1.35a): `DeriveChaincodeFromRootKey(priv)` (`PBW:835-841`,
  `AU:3423-3425`):
  ```
  chaincode = ArmoryHMAC_SHA256(key = hash256(rootPriv32), msg = b"Derive Chaincode from Root Key")
  ArmoryHMAC(key, msg) (AU:1823-1832, HMAC256 = HMAC(key,msg,sha256,32)):
      B = 32                                  # !! uses the DIGEST size as the block size
      if len(key) > B: key = sha256(key)
      key = key padded with 0x00 to B bytes
      return sha256( (key ^ 0x5c*B) || sha256( (key ^ 0x36*B) || msg ) )
  ```
  This is **not** RFC 2104 HMAC-SHA256 (which uses a 64-byte block). Verified: all three
  fixture root chaincodes equal ArmoryHMAC and differ from standard HMAC-SHA256.
* Older wallets have a **random** chaincode (`PBW:836`) — a reader must always use the
  chaincode stored in the root record; derive only when restoring from a 1.35a+ paper
  backup that omits it.

### 7.2 Chained private key (`CryptoECDSA::ComputeChainedPrivateKey`, `EUc:719-791`)
```
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
fn chained_priv(priv32, chaincode32, pub65 = None) -> priv32':
    if pub65 is empty: pub65 = ComputePublicKey(priv32)        # uncompressed 04||X||Y
    mult = chaincode32 XOR hash256(pub65)                       # byte-wise (done as 8×u32, endian-neutral)
    priv' = (int_be(mult) * int_be(priv32)) mod n               # a_times_b_mod_c
    return be32(priv')                                          # zero-padded 32 bytes
```
### 7.3 Chained public key (`ComputeChainedPublicKey`, `EUc:795-843`)
```
fn chained_pub(pub65, chaincode32) -> pub65':
    mult = chaincode32 XOR hash256(pub65)
    return serialize_uncompressed( int_be(mult) · Point(pub65) )
```
`chained_pub(pub(priv)) == pub(chained_priv(priv))`. The hash is always over the **65-byte
uncompressed** encoding. Index i+1 is derived from index i; index 0 from the root (−1).
Python wraps both in `safeExtendPrivateKey/PublicKey` (`PBA:425-517`) which compute twice
(three times on mismatch), return empty on persistent mismatch, and **append
`"PrvChain (pkh, mult): <hash160 hex>,<mult hex>"` lines to `multipliers.txt`** in the
Armory home dir (`AU:444`). The log is a side effect, not needed for compatibility (and
leaks the multiplier — do not replicate).

### 7.4 Keys, addresses
* Public keys are always 65-byte uncompressed in wallet files; `isCompressed()` is always
  `False` (`PBA:172-174`). Compressed form is only used for PKCC export (§9.2).
* Address = P2PKH: `base58( ADDRBYTE ‖ hash160(pub65) ‖ hash256(ADDRBYTE‖hash160)[:4] )`
  (`PBA:160-162`, `AU:2088-2099`).
* Private key export (WIF): `base58(PRIVKEYBYTE ‖ priv32 ‖ hash256(...)[:4])`, never with
  the compressed `01` suffix (`AU:2062-2085`, `AU:2880-2884`).
* Signing: `SignData` = ECDSA over `sha256(sha256(msg))` (first SHA in Armory, second by
  Crypto++), RFC6979 when `detSign` (`EUc:607-665`); out of scope here.

---

## 8. Imported keys, address pool, highest-used index

### 8.1 Imported keys (`importExternalAddressData`, `PBW:2440-2557`)
* Requires a private key unless the wallet is watching-only (`PBW:2462-2469`).
* Optional 4-byte checksums for priv/pub/addr are verified/corrected with
  `verifyChecksum`.
* Record: `chainIndex=-2`, `chaincode=ff×32`, `timeRange=[firstTime, lastTime]`,
  `blkRange=[firstBlk,lastBlk]` (defaults `UINT32_MAX, UINT32_MAX, 0, 0`).
  Encrypted wallet: must be unlocked; record gets a random IV and is encrypted with the
  current `kdfKey` (`PBW:2515-2525`, `2546-2549`). Appended as a type-0x00 entry.
* Watching-only import without private key: `createFromPublicKeyData` (flags `0x02`) or
  `createFromPublicKeyHash160` (flags `0x00`, pubkey slot empty) (`PBW:2529-2533`).
* Bug: `PBW:2497` tests `isinstance(pubKey, str)` where `addr20` was meant.
* Imported keys are not recoverable from the root; deleting them writes a type-0x04 entry.

### 8.2 Address pool ("keypool"/lookahead)
* `addrPoolSize`: 100 (mainnet default `--keypool`), 10 on testnet; `setAddrPoolSize`
  refuses < 5 (`PBW:1044-1051`).
* `fillAddressPool(numPool)` (`PBW:1006-1041`): `toCreate = max(numPool − (lastComputed −
  highestUsed), 0)`; each new address = `extendAddressChain(kdfKey)` of
  `lastComputedChainAddr160`, appended via `walletFileSafeUpdate` (`PBW:966-1003`).
  Fixtures: `lastComputed − highestUsed = 10` in all three (testnet pool).
* New wallet: root (−1) + index 0 written at creation, `highestUsed = −1`, then
  pool filled (`PBW:869-923`).

### 8.3 highestUsedChainIndex (i64 at offset 326)
* `getNextUnusedAddress` (`PBW:951-963`): top up pool if `lastComputed − highestUsed <
  max(pool−1, 1)`; `advanceHighestIndex(1)`; `touch()` the record and rewrite it.
* `advanceHighestIndex(ct)` (`PBW:927-935`): `clamp(highestUsed+ct, 0, lastComputed)`, write
  8 bytes at 326, refill pool. (`rewindHighestIndex` cannot go below 0.)
* `peekNextUnusedAddr` = index `highestUsed+1` (`PBW:943-948`). Fixture: GDHFnMQ2
  highestUsed=10 → index 11 → `muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG` =
  `EXPECTED_TIAB_NEXT_ADDR` (`testArmoryDTiab.py:58`).
* Signing bumps it to the max chain index used (`PBW:2756-2759`); blockchain scans
  (`detectHighestUsedIndex`, `PBW:1074-1107`) may write it. Bug: `freshImportFindHighestIndex`
  calls `detectHighestUsedIndex(True)` — `True` lands in `startFrom` (=1), not
  `writeResultToWallet` (`PBW:1141`).

---

## 9. Watching-only export, wallet copies, PKCC

### 9.1 Fork watching-only (`forkOnlineWallet`, `PBW:1332-1375`)
New wallet object: same fileID/version/magic/createDate/uniqueIDBin/highestUsed;
`useEncryption=False`, `watchingOnly=True` (header flags `0x02`), **KDF block zero**
(`kdf=None`). Labels: `(shortLabel + ' (Watch)')[:32]`, `(longLabel + ' (Watching-only
copy)')[:256]` (the WalletFrames path passes `'(Watching-Only) ' + descr`,
`ui/WalletFrames.py:1038-1039`). Each record: `copy()`, then encPriv/plainPriv/IV wiped,
`useEncryption=False`, pending cleared → flags `0x02`, priv/IV slots empty; `chainDepth` is
copied unchanged. Comments copied. Written with `writeFreshWalletFile` (`PBW:1152-1171`):
header, then key entries in dict order, then comments (only the current text of each);
**its `newName/newDescr` parameters are ignored**. No `_backup` file is created by this path.
GUI default name: `<walletpath stem>_WatchOnly.wallet` (`ui/WalletFrames.py:1030-1033`,
`qtdialogs.py:4626`, `qtdialogs.py:11493-11505`).

`createNewWalletFromPKCC(pub65, chaincode)` (`PBW:684-765`) produces the same byte format
from a root pubkey + chaincode: labels `"<ID> (Watch)"` / `"<ID> (Watching-only copy)"`,
file `armory_<ID>_WatchOnly.wallet`, root record flags `0x02`.

### 9.2 Root PKCC text file (`.rootpubkey`, `writePKCCFile`, `PBW:1311-1328`)
```
line 1: "1"                                     # str(PYROOTPKCCVER)
line 2: ET16( verByte ‖ uniqueIDBin[6] ‖ hash256(verByte‖uniqueIDBin)[:2] ), 4-char groups joined by ' '
          verByte = 0x01 | (0x80 if compressedRootPub[0]==0x03 else 0)     # PBW:1284-1286
lines 3-6: for each 16-byte chunk c of (compressedRootPub[1:33] ‖ chaincode[32]):
          makeSixteenBytesEasy(c) = ET16(c ‖ hash256(c)[:2]) as "xxxx xxxx xxxx xxxx  xxxx xxxx xxxx xxxx  xxxx"
```
ET16 ("EasyType16") maps hex digits `0123456789abcdef` → `asdfghjkwertuion`
(`AU:2161-2174`, `AU:2178-2187`). Reading (`qtdialogs.py:12811-12816`):
`sign = ((ver & 0x80)>>7) + 2`, pub = `UncompressPoint(sign ‖ x32)`; checksum lines are
verified with `readSixteenEasyBytes` (single-byte correction, `AU:2189-2205`).

### 9.3 Other copies (`ArmoryQt.makeWalletCopy`, `ArmoryQt.py:1726-1771`)
* "same": `writeFreshWalletFile` (byte format identical, entries reordered).
* "decrypt": `makeUnencryptedWalletCopy` (`PBW:1175-1198`) writes a fresh copy, opens it,
  `changeWalletEncryption(None)`, deletes the copy's `_backup` file.
* "encrypt": `makeEncryptedWalletCopy` (`PBW:1201-1230`): if the wallet is unencrypted it
  temporarily encrypts **the original in place** (new KDF params), copies, then decrypts
  again — the original's KDF block stays changed.
* Default names: `armory_<ID>_<suffix>.wallet`, watch-only `armory_<ID>_<suffix>_WatchOnly.wallet`.

---

## 10. Atomic update protocol, backup file, flag files

### 10.1 File names (`getWalletPath`, `PBW:1727-1740`; `getSuffixedPath` `PBW:3172-3180`)
`stem, ext = splitext(path)`; if `stem` ends with `_` → `stem + suffix + ext`, else
`stem + '_' + suffix + ext`. For `armory_ID_.wallet`:

| Role | Name |
|---|---|
| main | `armory_ID_.wallet` |
| backup | `armory_ID_backup.wallet` |
| main-update flag | `armory_ID_update_unsuccessful.wallet` |
| backup-update flag | `armory_ID_backup_unsuccessful.wallet` |

For `X_WatchOnly.wallet` → `X_WatchOnly_backup.wallet`, etc. Flag files are empty
(`touchFile`, `AU:3684-3692`). Wallet discovery skips names ending in `backup.wallet` and
files whose first 8 bytes are not the magic (so flag files are skipped) (`AU:1032-1045`).
The backup is a byte-identical copy (fixtures: each `_backup` file `cmp`-identical to main).

### 10.2 `walletFileSafeUpdate(updateList)` (`PBW:2148-2327`)
Update items: `[ADD(0), dtype, hash, payload]` (appended, returns new entry offset) or
`[MODIFY(1), offset, bytes]` (in-place overwrite). Steps:
1. `doWalletFileConsistencyCheck()` (§10.3).
2. Build the append blob (type byte ‖ hash ‖ record | u16 len ‖ comment).
3. `touch(mainFlag)`; append blob to main, fsync; apply all MODIFYs to main, fsync.
   On `IOError`: copy backup → main, remove mainFlag, return `[]`.
4. `touch(backupFlag)`; `remove(mainFlag)`.
5. Append the same blob to backup, fsync; apply MODIFYs, fsync. On `IOError`: copy main →
   backup and `remove(mainFlag)` — **bug**: mainFlag is already gone, so this raises
   (`PBW:2318-2321`); intended was `remove(backupFlag)`.
6. `remove(backupFlag)`; return list of offsets (entry start for ADD — the type byte —
   or the given offset for MODIFY).
Callers update in-memory state only after a non-empty return.

### 10.3 Consistency check / recovery (`doWalletFileConsistencyCheck`, `PBW:2330-2391`)
Run on every read (`readWalletFile(verifyIntegrity=True)`, `PBW:2073-2078`) and before
every update:
```
if !exists(backup): touch(backupFlag); copy main→backup; remove(backupFlag)
if exists(backupFlag) && exists(mainFlag): copy main→backup; remove both     # interrupted between steps 4a/4b
elif exists(mainFlag):   copy backup→main; remove(mainFlag)                  # main may be corrupt
elif exists(backupFlag): copy main→backup; remove(backupFlag)                # backup update interrupted
```
The "both flags" state arises when the process dies between `touch(backupFlag)` and
`remove(mainFlag)` in step 4 (`PBW:2291-2296`; simulated by `interruptTest2`); main is
complete and fsynced at that point, so copying main→backup is correct. Test coverage: `testPyBtcWallet.py:283-343`.

---

## 11. Private-key text parsing (`AU:2802-2884`)
* `decodeMiniPrivateKey(s)` (`AU:2802-2818`): len ∈ {22, 26, 30}; `sha256(s+'?')[0]` must be
  `0x00` (`0x01` → "PBKDF2 mini keys not supported", else invalid); key = `sha256(s)`.
* `parsePrivateKeyData(s)` (`AU:2822-2877`): hex alphabet check is `'01234567890abcdef'`
  on `s.lower()`; base58 set as §1.3.
  - Base58-only and len 22 or 30 → mini key (len 26 is **not** accepted here).
  - Base58-only and len 48–52 → `base58_to_binary`.
  - Hex (also wins when a string is valid in both) → `hex_to_binary`.
  - Decoded len 36 → `priv[32] ‖ chk4` verified with `verifyChecksum`.
  - Decoded len 37 and first byte == `PRIVKEYBYTE` → WIF; verify `hash256(first33)[:4]`;
    strip the prefix.
  - Decoded len 33 or 37 ending in `01` (and not handled above) → `CompressedKeyError`.
    (A 38-byte compressed WIF falls through and is returned unparsed.)
  - Checksum failure → `InvalidHashError`.

---

## 12. SWIG surface used by the wallet code
`CppBlockUtils.i` `%include`s all of `EncryptionUtils.h` and `BtcUtils.h`
(`SWIG:256-257`); `std::string` ↔ `BinaryData` typemaps (`SWIG:94-140`). Calls actually
made from the wallet/address code:
`SecureBinaryData(str)`, `.toBinStr/.toHexStr/.getSize/.copy/.destroy`, `.getHash256()`,
`.getHash160()`, `.GenerateRandom(n[, entropy])`; `KdfRomix(mem,iter,salt)`,
`.computeKdfParams`, `.usePrecomputedKdfParams`, `.DeriveKey`, `.getMemoryReqtBytes`,
`.getNumIterations`, `.getSalt`; `CryptoAES().EncryptCFB/DecryptCFB`;
`CryptoECDSA().ComputePublicKey`, `.CheckPubPrivKeyMatch`, `.VerifyPublicKeyValid`,
`.ComputeChainedPrivateKey`, `.ComputeChainedPublicKey`, `.CompressPoint`,
`.UncompressPoint`, `.SignData`, `.VerifyData`; `BtcUtils().getHash160_SWIG`,
`.ripemd160_SWIG` (`AU:1811-1820`). `hash256`/`sha256` on the Python side use `hashlib`.

---

## 13. Rust read algorithm (summary)
1. Recovery step: apply §10.3 against the sibling files (or just open main read-only and
   warn if a flag file exists).
2. Require `len ≥ 2107`, magic `\xbaWALLET\x00`, version ≥ 13500000, network magic and
   `uniqueIDBin[5]` matching the configured network; refuse flag bit 2.
3. Parse header (§2), KDF block (§2.3) with checksum correction, skip crypto block, parse
   root (§3.3), skip 1024.
4. Loop entries (§4) until EOF; unknown type → advance 1 byte; type 3 → error.
5. Build maps keyed by chainIndex/addr160; last comment per hash wins.
6. Validate: `hash160(pub)==addr160`; for unencrypted records `pub(priv)==pub`; chained
   records re-derivable from root (optional, expensive).
7. Encrypted: derive key with §5 only when the user unlocks; verify on root (§6.3).

---

## 14. Test vectors

### 14.1 Copied verbatim from repository tests
| Constant | Value | Source |
|---|---|---|
| `WALLET_ROOT_ADDR` (hash160 of root, priv `aa`×32) | `5da74ed60a43a7ff11f0ba56cb0192b03518cc56` | `pytest/testPyBtcWallet.py:25` |
| `NEW_UNUSED_ADDR` (hash160 of chain index 0, chaincode `ee`×32) | `fb80e6fd042fa24178b897a6a70e1ae7eb56a20a` | `pytest/testPyBtcWallet.py:26` |
| wallet ID for that wallet (testnet, tests run with `--testnet`, `pytest/Tiab.py:6`) | `3VB8XSoY` | `pytest/testPyBtcWallet.py:32` |
| root priv / chaincode / IV / passphrases | `'\xaa'*32`, `'\xee'*32`, `'77'*16`, `'A self.passphrase'`, `'A new self.passphrase'`, `'hello'` | `pytest/testPyBtcWallet.py:42-47,147` |
| KDF params set in test | mem `1024`, iter `999`, salt `'00'*32` | `pytest/testPyBtcWallet.py:222-225` |
| Comment I/O | addr `'\x1f'*20` → `'This is my normal unit-testing address.  Corrected!'`; tx `'\x2f'*32` → `'This is fake tx... no tx has this hash.'` | `pytest/testPyBtcWallet.py:417-430` |
| `INIT_VECTOR` | `77777777777777777777777777777777` | `pytest/testPyBtcAddress.py:21` |
| `PRIVATE_KEY` | `aa`×32 | `pytest/testPyBtcAddress.py:30` |
| `FAKE_KDF_OUTPUT1` / `2` | `11`×32 / `22`×32 | `pytest/testPyBtcAddress.py:38-39` |
| `TEST_ADDR1_PRIV_KEY_ENCR1` = AES-CFB(key 11×32, IV 77×16, aa×32) | `500c41607d79c766859e6d9726ef1ea0fdf095922f3324454f6c4c34abcb23a5` | `pytest/testPyBtcAddress.py:22` |
| `TEST_ADDR1_PRIV_KEY_ENCR2` = AES-CFB(key 22×32, IV 77×16, aa×32) | `7966cf5886494246cc5aaf7f1a4a2777cd6126612e7029d79ef9df47f6d6927d` | `pytest/testPyBtcAddress.py:23` |
| `TEST_ADDR1_PRIV_KEY_ENCR3` = chained priv #1 (aa / ee) (misnamed: it is plaintext) | `0db5c1e9a8d1ebc0525bdb534626033b948804a9a34871d67bf58a3df11d6888` | `pytest/testPyBtcAddress.py:24,200` |
| `TEST_ADDR1_PRIV_KEY_ENCR4` = chained priv #2 | `5db1314a20ae9fc978477ab3fe16ab17b246d813a541ecdd4143fcf082b19407` | `pytest/testPyBtcAddress.py:25,210` |
| `TEST_PUB_KEY1` = chained pub #2 | `046c35e36776e997883ad4269dcc0696b10d68f6864ae73b8ad6ad03e879e43062a0139095ece3bd653b809fa7e8c7d78ffe6fac75a84c8283d8a000890bfc879d` | `pytest/testPyBtcAddress.py:27,244` |
| Satoshi pubkey / hash160 | `04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284` / `65a4358f4691660849d9f235eb05f11fabbd69fa` | `pytest/testPyBtcAddress.py:382-383` |
| Empty `PyBtcAddress().serialize()[:20]` = 20×00 and unserialize raises `UnserializeError` | — | `pytest/testPyBtcAddress.py:50-53` |
| Mini key | `S4b3N3oGqDqR5jNuxEvDwf` → `0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d` | `pytest/testArmoryEngineUtils.py:149-151` |
| `ripemd160('\x0f\xfd')` | `13988143ae67128f883765a4a4b19d77c1ea1ee9` | `pytest/testArmoryEngineUtils.py:78-79,171` |
| `hash160('\x0f\xfd')` | `d418dd224e11e1d3b37b5f46b072ccf4e4e26203` | `pytest/testArmoryEngineUtils.py:172` |
| Version ints | `(0,50,0,0)`↔`5000000`↔`'0.50'`; `(1,0,12,0)`↔`10012000`↔`'1.00.12'`; `(0,20,0,108)`↔`2000108`↔`'0.20.0.108'` | `pytest/testArmoryEngineUtils.py:125-147` |
| BinaryPacker sequence (u8,u16,u32,u64=0xff; i8..i64=−1; varint 78; varstr 'abc'; float 1.23456789; 'ff'×3; 'ff'×3 width 4) | `ffff00ff000000ff00000000000000ffffffffffffffffffffffffffffff4e0361626352069e3fffffffffffff00` | `pytest/testArmoryEngineUtils.py:535-569` |
| AES-256 CFB NIST (pt = 16×00) | key 00×32, IV `80`+00×15 → `ddc6bf790c15760d8d9aeb6f9a75fd4e`; key 00×32, IV `014730f80ac625fe84f026c60bfd547d` → `5c9d844ed46f9885085e5d6a4f94c7d7`; key `ffffffffffff`+00×26, IV 00×16 → `225f068c28476605735ad671bb8f39f3` | `cppForSwig/old_not_very_good_tests.cpp:1452-1492` (verified by this author with AES-CFB) |
| secp256k1 helpers (scalar mult mod n, point mult/add/inverse, compressed/uncompressed pairs) | see file | `cppForSwig/gtest/CppBlockUtilsTests.cpp:10640-10674` |

`testPyBtcAddress.py` scenario that a Rust port should replay (`:56-326`): encrypt/lock
with key1 → ENCR1; changeEncryptionKey key1→None→key2 → ENCR2 (same IV); key2→key1 →
ENCR1; locked root (key1, IV 77) chained twice with key → priv equals ENCR4; chained twice
**without** key (pending) → pub equals `TEST_PUB_KEY1`, and after `unlock(key1)` the priv
equals ENCR4.

`verifyChecksum` cases (`pytest/testArmoryEngineUtils.py:112-121`), with
`data = 11‖aa×31`, `dchk = hash256(data)[:4]`:
`verify(data)`→data; `verify(reverse(data))`→data ("reversed"); `11‖aa×30‖ab` with fix → data,
without fix → `''`; two-byte error `11‖aa×29‖abab` → `''` either way.

### 14.2 Derived by linking the real `cppForSwig/EncryptionUtils.cpp` (not repo constants)
Harness compiled from unmodified repo sources + bundled Crypto++; the Python port in this
spec reproduces every value.

| Input | Output |
|---|---|
| KdfRomix pw=`"abcde"`, mem=1024, iter=1, salt=00×32 | `bc1f2cd96b766e91a7e2340f9564073f232d874778bce25c565ad26ea0ff3b6d` |
| KdfRomix pw=`"abcde"`, mem=1024, iter=3, salt=00×32 | `ddf620a364263c50c2abdbc85c230b586f52881268c24bd2ffe58d96080b3db8` |
| KdfRomix pw=`"This is my first password"`, mem=65536, iter=2, salt=`1ee82e6ef29655e597da9954b64aab87b470126c7b28b76d3d41168946305ffe` | `55562b96f019d234ea7bef95b1c8a096010eff56bb5bbf3c6332e5c6963ccb2a` |
| KdfRomix pw=`"abcde"`, mem=2097152, iter=2, salt=`1ee82e6e…305ffe` (GDHFnMQ2's stored params) | `21d6716fcaebe82fd1f1a6ef43f244b759c5a888301cd1dae1685b6dbf1b847a` |
| KdfRomix pw=`"abcde"`, iter=0 | `6162636465` (passphrase returned unchanged) |
| pub0 = ComputePublicKey(aa×32) | `046a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb336b6fbcb60b5b3d4f1551ac45e5ffc4936466e7d98f6c7c0ec736539f74691a6` |
| multiplier for pub0, chaincode ee×32 (= ee×32 XOR hash256(pub0)) | `0a9b2577729fc5b719275c036b8101a085396e4f95ed1e3a65b447bdfe00c8e3` |
| pub1 = ComputeChainedPublicKey(pub0, ee×32) | `04c742682e265cffac36ec1445e457d83ff17d82873afecbb2e102b93d84ccd02048daae8d93e0a2972ac5436823049249d3a78fdfff2adf52ca603e28e761d669` (hash160 = `NEW_UNUSED_ADDR`) |
| AES-CFB outputs for the §14.1 key/IV cases | identical to `TEST_ADDR1_PRIV_KEY_ENCR1/2` |

### 14.3 Derived with the spec's Python port (structure fixture-verified; not run on Armory)
* `DeriveChaincodeFromRootKey(aa×32)` = `cd0784defd9a0fbc4ecc1b306eb7679b3a9c5a23f340b2453aadc482ed10c5dc`.
* Mainnet ID for the `aa/ee` wallet would be `3VB8XSmd` (testnet `3VB8XSoY`).
* Unencrypted root record for priv aa×32, chaincode ee×32, IV 77×16 (as `createNewWallet(
  withEncrypt=False, IV=77…)` stores it), fresh time ranges:
  ```
  5da74ed60a43a7ff11f0ba56cb0192b03518cc56 2a446496 60fecd00 0300000000000000
  eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee c93a79dd
  ffffffffffffffff ffffffffffffffff
  77777777777777777777777777777777 10b7b8f7
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 6dc8daeb
  046a04ab…f74691a6 (pub0 above) e475cb99
  ffffffff00000000 0000000000000000 ffffffff 00000000
  ```
* Same record encrypted with KDF(`"abcde"`,1024,1,00×32) = `bc1f2c…3b6d`: flags `07…`,
  priv slot `5b4d449403396ef20b33ee34553d7726d48878a70dba5f32d9cca49d6f220ff2`, chk
  `993c2522`; all other bytes identical.

### 14.4 Fixture facts (TIAB, testnet) — `pytest/Tiab.py:28-35`, `pytest/testArmoryDTiab.py:52-108`
Passphrase used by tests at runtime (fixtures on disk are **unencrypted**): `PASSPHRASE1 =
'abcde'` (`testArmoryDTiab.py:52`, applied at `:449-456`).

| Wallet | size | label | createDate | highestUsed | lastComputed | root addr160 | root chaincode |
|---|---:|---|---:|---:|---:|---|---|
| GDHFnMQ2 | 7838 | `Primary Wallet` | 1392443085 | 10 | 20 | `536364abd1d2084bf229e0d3805e7b3913aaf011` | `e7a347003d10e1be87125da4dde514a009c721fcb4f86844bf5f66cf186eda84` |
| vzgEfJrJ | 5977 | `Secondary Wallet with a really r` | 1392649402 | 4 | 14 | `65971cb5434bedf34648378b167c02430bab3235` | `9126a905db7c9bb1bc640106c010a1a6be9aee1e968edf8e30be40620648cbac` |
| DZMmtb2v | 5719 | `Third Wallet` | 1399999349 | 3 | 13 | `b1a049c9eaea2746b36fc317d4096571aee71c81` | `a76fa204771ff423a0cf5b6abe1ea9166583e66449df057ba6ad8768299fa4b1` |

GDHFnMQ2 also holds 6 address comments `[[ Change received ]]` (entries at 5461, 5763,
6065, 6883, 7234, 7536) and one tx comment `Funding 2-of-3` at 6927. Address ↔ WIF ↔ chain
index (all confirmed against stored plaintext keys):

| Wallet | idx | Address | WIF (`testArmoryDTiab.py`) |
|---|---:|---|---|
| GDHFnMQ2 | 0 | `muxkzd4sitPbMz4BXmkEJKT6ccshxDFsrn` | `92vsXfvjpbTj1sN75VSV2M7DWyqoVx5nayp3dE7ZaG9rRVRYU4P` (:70-71) |
| GDHFnMQ2 | 1 | `mtZ2d1jFZ9YNp3Ku5Fb2u8Tfu3RgimBHAD` | `934MLhycJEAWL4kMbFt6JRSkNcgEtQXN3ha6Wh8WZyD85cZZZ4N` (:73-74) |
| GDHFnMQ2 | 2 | `mhrpYhQLgYgAvYs1A4E8Z4Dv4ZoZPyLbLS` | `91rTQa47dLQhNGDenejW9qxcMTL73GRG347zKfa3qVvzun7ZcNe` (:76-77) |
| GDHFnMQ2 | 7 | `mikxgMUqkk6Tts1D39Hhx6wKEeQbBH3ons` | `92fXG1foeHfn8DYEwTXggCPrFEEY6KpokqoJkp9EhpJw5boc3GY` (:82-83) |
| GDHFnMQ2 | 11 | `muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG` (next unused) | — (:58) |
| vzgEfJrJ | 0..3 | `mzkKrXNPU6nfBpZCKLmwueb9MvSFaKPDMD`, `n2DLXxVZSNBfzXsAm4HewpsfAGBpgTW6DH`, `mhbmvVedo4i67maX6pfw9trcBWQQ3yXgkB`, `mk7pAQ7YdmnwWaGFCgwiKiEbaGjyEsSVUE` | `91jZJ2BnJbk4B6zpqzJqVfbtaq4RMaPPvP7USr9rtWXusSAYrq7`, `93LLsm4n19Dwbp6zbnmuvHmMjEJFR23h4xstnDnEBYMWSkXaFMT`, `92aUXStPSfHDXydGh9MsBnnyacNzJwgWBC4G8W5BiTFkTJpeHEH`, `92gYPs8i6qvSmc8moBAaWLB7M16kX5MBpbGoUygUmQTdrxkNnwR` (:87-98) |
| DZMmtb2v | 0..2 | `mnHywMYRuMyYeamyGhUPJLFSsoWbNAnsNz`, `mpXd2u8fPVYdL1Nf9bZ4EFnqhkNyghGLxL`, `mmfN9oj2wtMTCACKJz7fUcDeAczz4kucvV` | `9295sDHkX1xDMzSxit3Bvi8GdLUQq1JFktBQFB8Ca45aLaw8neN`, `92Mic29J44mKLn4qKXm31mMv45BtEnywBnJh36jn1Rk2RT9PTsK`, `92ymyLuiEUJJz5madzhPtBTa3of46vLXDSuFPNMAA6DMLSeKA8S` (:100-108) |

### 14.5 Stale offsets in `testPyBtcWallet.py` (copy, but do not trust)
The byte-corruption test seeks to `326` ("second byte in KDF"), `838, 885, 929, 954, 1000`
("each checksummed field in root addr"), `1261+21+{838,…}` ("first non-root addr") and
`977` ("the CHECKSUM") (`pytest/testPyBtcWallet.py:351-412`). These match a layout **8
bytes shorter** than 1.35: in the real (fixture-verified) layout 326 is `highestUsed`, the
KDF block starts at 334, the root record at 846 and the first entry at 2107; 838 lies in
the crypto block, 977 is inside the root's private-key data. The test still "passes"
because it only asserts that main and backup differ afterwards. Use §2/§3 offsets.

---

## 15. Quirks and bugs a compatible implementation must know

1. Entry type is **1 byte**, not 4 (docstring wrong). Unknown type bytes are skipped one
   byte at a time (§4).
2. Flag bitsets are **LSB-first** (`flags[0]` = mask `0x01`).
3. Empty field = zeros + `5df6e0e2`; an all-zero value is indistinguishable from empty.
4. `verifyChecksum` accepts **byte-reversed** data and silently returns it reversed (§1.5).
5. Single-byte auto-correction rewrites the file on read (KDF block, root, every record).
6. Header network/magic mismatch is ignored by `readWalletFile` (should be fatal).
7. Labels are stripped of NULs at both ends; 32/256-byte labels have no terminator.
8. Chaincode HMAC uses a 32-byte block (non-RFC2104).
9. KDF: `nIter=0` ⇒ key = passphrase; index read as LE u32 of bytes 60..63; lookups = seq/2;
   iterations chain on the 32-byte output.
10. KDF block persists after decryption; IVs may be present on unencrypted records;
    depth may be 0 or −1 on normal records. Decide state from flags only.
11. Pending records store an ancestor's IV + ciphertext, not their own (§6.5); on unlock the
    "n2 fix" may substitute the previous chained record's pair; a fresh IV is generated
    when materialising.
12. Comments are overwritten by zeroing the body and appending; last one wins.
13. `writeFreshWalletFile` reorders entries (dict order) and ignores its label args.
14. `unserialize` calls non-existent `CryptoAES().ComputePublicKey` (§3.3).
15. `importExternalAddressData` type-check bug (`PBW:2497`); `chainIndex < -2` clamped.
16. `walletFileSafeUpdate` backup-failure path removes the main flag twice (`PBW:2320`).
17. `freshImportFindHighestIndex` passes `True` as `startFrom` (`PBW:1141`).
18. `setWalletLabels` does not truncate (`PBW:1864-1865`).
19. `makeEncryptedWalletCopy` permanently changes the source wallet's KDF parameters.
20. `parsePrivateKeyData` accepts 22/30-char mini keys only; `decodeMiniPrivateKey`
    also accepts 26.
21. `multipliers.txt` side-effect log of chain multipliers (do not replicate).
22. Root private keys are not checked to be in `[1, n−1]`; chained keys are reduced mod n.

## 16. Open uncertainties
* No encrypted, pending, imported, deleted or watching-only bytes exist in the fixtures;
  those layouts are derived from code (and the AES/KDF/chain primitives are independently
  verified). Recommend generating such fixtures with a Python-2 Armory build if one becomes
  available.
* Passphrase encoding for non-ASCII input depends on the PyQt4 `str()` conversion (likely
  fails or is Latin-1); treat passphrases as raw bytes.
* Pre-1.35 wallet formats are refused by this code and are not specified here.
* Paper-backup (SecurePrint, fragmented/SSS) formats are out of scope (see `qtdialogs.py`,
  `AU:2568-2742`, `AU:3442-3505`).
