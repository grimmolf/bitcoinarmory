# 08 — goatpig Armory "0.97" LMDB wallet format (research for a future importer)

Status: research notes, not yet an implementation spec · Source: `goatpig/BitcoinArmory` branch `dev`,
commit `d0294d5913c8c272fbc89ac14c7623dec5ea1404` (2026-05-20). Citations are `file:line` in that commit
(`W/` = `cppForSwig/Wallets/`). goatpig's code is MIT-licensed (file headers), so reading it to build a
compatible reader is fine for this AGPL tree.

## Findings that decide the importer's scope

- **0.97 was never released.** The last release is 0.96.5 (December 2018, `changelog.txt`, tags end at
  `v0.96.5`); the LMDB format exists only on the still-active `dev` branch. Real-world files are rare.
- **Two layers of encryption.** A control passphrase protects the whole file (labels and addresses
  included); a separate passphrase protects private keys. With an empty control passphrase the file opens
  without input (default key stored in clear).
- **Opening a file writes to it.** Every open appends a key-rotation record, so an importer must work on
  a copy, never the user's original.
- **What the GUI creates:** Armory legacy-chain wallets (the 1.35 chain, "Armory200" flavour), not BIP32.
  These map onto this project's `legacy-1.35` account; addresses whose type differs from the account
  default (compressed / SegWit on the legacy chain) need per-address types, which our legacy account does
  not model yet.
- **BIP39 wallets** (restore only) carry 24 words with an empty BIP39 passphrase: they migrate as a plain
  restore, BIP44/49/84 accounts included. Nested SegWit (BIP49) has no account type in our v2 format yet.
- **No equivalent** for salted-BIP32 and ECDH accounts (key-by-key export only); no Taproot in goatpig.
- **Fixtures:** none in the repo (tests create wallets). An oracle built from goatpig's C++ is needed, as
  was done for 1.35 (`tools/legacy-oracle`). goatpig's 1.35 test input `gtest/input_files/legacy.wallet`
  is byte-identical to our `fixtures/legacy/encrypted/goatpig-legacy-testnet.wallet`.


## Part A — goatpig Armory (dev / "0.97") — LMDB wallet file storage & encryption spec

Source: shallow clone at `/home/user/goatpig/bitcoinarmory`, branch `dev`, HEAD `d0294d5`.
All paths below are relative to `cppForSwig/` unless stated. `W/` = `cppForSwig/Wallets/`.
Every claim cites file:line. "unverified" = could not be confirmed from source in this clone.

---

### 0. Primitive encodings (needed everywhere)

| Primitive | Encoding | Citation |
|---|---|---|
| `put_uint16_t` / `put_uint32_t` (default) | little-endian (default arg `LE`; LE path = `memcpy` of host value, i.e. host order, LE on all supported targets) | Utils/BinaryData.h:640-641; Utils/BinaryData.cpp:1578-1606 |
| `get_uint16_t` / `get_uint32_t` (default) | little-endian | Utils/BinaryData.h:399-400, 459-461 |
| `put_var_int` | Bitcoin CompactSize: `<0xfd` 1 byte; `0xfd`+u16LE; `0xfe`+u32LE; `0xff`+u64LE | Utils/BinaryData.cpp:1651-1670 |
| `put_String` | raw bytes, **no length prefix** | Utils/BinaryData.cpp:1702-1705 |
| `WRITE_UINT32_BE` / `READ_UINT32_BE` | big-endian u32 | Utils/BinaryData.h:34, 54 |
| "packet" (`DBUtils::getDataRefForPacket`) | `varint(len) ‖ payload`, len must equal remaining size | Utils/DBUtils.cpp:250-259 |
| `Hash256` (`getHash256`) | SHA256(SHA256(x)) | Utils/Cryptography.cpp:731-735 |
| `HMAC256(key,msg)` / `HMAC512(key,msg)` | HMAC-SHA256 / HMAC-SHA512, **first arg is the key** | Utils/BtcUtils.cpp:80-89, 193-202, 240-254; Utils/Cryptography.cpp:742-761 |
| SHA-512 | libbtc `sha512_Raw` | Utils/Cryptography.cpp:750-753 |
| AES | AES-256-CBC via libbtc `aes256_cbc_encrypt/decrypt`, padding flag `1` commented "PKCS #5 padding"; output size always `(len/16 + 1)*16` (so a full pad block is added when len%16==0) and the call is checked to return exactly that size. IV must be 16 bytes. Empty plaintext → returns empty (no encryption). | Utils/Cryptography.cpp:229-286; BLOCK_SIZE = AES_BLOCK_SIZE Utils/Cryptography.cpp:35 |
| secp256k1 pubkey | `computePublicKey(priv, compressed=false)` default **uncompressed (65 B)** | Utils/Cryptography.h:174; Utils/Cryptography.cpp:397-420 |
| ECDH (`pubKeyScalarMultiply`) | `secp256k1_ec_pubkey_tweak_mul`, output serialized in the **same form as the input** (33-byte in → compressed 33-byte out) | Utils/Cryptography.cpp:576-602 |
| `computeDataId(data, msg)` | `HMAC256(key=Hash256(data), msg)` → **last 16 bytes** | Utils/BtcUtils.cpp:1044-1064 |

Note: libbtc is **not vendored** in this clone (CMakeLists.txt:39-53 points at an external `THIRD_PARTY_PATH/libbtc`); the exact padding implementation is therefore "PKCS#5/7 per the comment at Utils/Cryptography.cpp:248 and the `+1` block math at :237 — libbtc source unverified".

---

### 1. File layout

#### 1.1 File naming
* New wallet: `<folder>/armory_<masterId>_<suffix>.lmdb`, suffix default `"wallet"` → `armory_<masterId>_wallet.lmdb` (W/IOHeader.h:73-79). Used by `createFromSeed` (W/Wallets.cpp:1179-1182, 1236-1239) and `createBlank` (W/Wallets.cpp:1400-1403).
* WO wallet created from a public seed: suffix `"WatchingOnly"` → `armory_<masterId>_WatchingOnly.lmdb` (W/Wallets.cpp:1358-1361).
* WO fork of an existing file: stem with everything from the last `_` removed, then `"_WatchingOnly.lmdb"` appended, same folder (W/Wallets.cpp:2355-2362).
* Gtest confirms the standard name: `"armory_" + seed->getMasterId() + "_wallet.lmdb"` (gtest/WalletTests.cpp:4169).
* Compaction temp files live in a sibling folder `_delete_me` named `compactCopy-<hex>` / `swapOld-<hex>` (W/WalletFileInterface.cpp:26-28, 806-860).

#### 1.2 LMDB environment
* Single-file env: `mdb_env_open(path, MDB_NOSUBDIR | flags, 0600)` (lmdbpp/lmdbpp.cpp:575). (With `MDB_NOSUBDIR`, LMDB's lock file is `<path>-lock` — standard LMDB behaviour, not in this repo.)
* Flags passed: `MDB_NOTLS` (W/WalletFileInterface.cpp:636).
* Map size: `100*1024*1024` bytes (W/WalletFileInterface.cpp:637).
* `maxdbs` = `dbCount_` (lmdbpp/lmdbpp.cpp:570), set to 2 at open, 3 after creation, then `headerMap.size()+2` after load (W/WalletFileInterface.cpp:57, 64, 73, 120). The env is closed/reopened when the count grows (W/WalletFileInterface.cpp:666-688).
* Named DBs opened with `mdb_open(txn, name, MDB_CREATE)`; default comparator (lmdbpp/lmdbpp.cpp:592-601). Puts use flags 0 (lmdbpp/lmdbpp.cpp:214).

#### 1.3 Named databases

| Name | Layer | Contents | Citation |
|---|---|---|---|
| `control_db` | **raw** LMDB (NOT EncryptedDB) | control header, control seed, control master EncryptionKey, control KDF | CONTROL_DB_NAME W/WalletFileInterface.h:106; raw tx W/WalletFileInterface.cpp:257-260, 277-283 |
| `WalletHeader` | EncryptedDB | one header per sub-wallet (key `0xB0‖walletId`), `MASTERID_KEY`, `MAINWALLET_KEY` | WALLETHEADER_DBNAME W/WalletHeader.h:34; W/WalletFileInterface.cpp:108-117, 146-180, 538-545; W/Wallets.cpp:146-158, 225-233 |
| `<walletId>` (one per header) | EncryptedDB | wallet data: seed, root asset, accounts, assets, labels, wallet EncryptionKeys/KDFs | db name = walletID W/WalletHeader.cpp:50-53; opened W/WalletFileInterface.cpp:122-125, 548-574 |

A typical single-wallet file therefore has 3 named DBs: `control_db`, `WalletHeader`, `<walletId>`. Custom sub-DBs (`WalletHeader_Custom`) add more (W/Wallets.cpp:763-780).

#### 1.4 Records in `control_db` (raw, values stored exactly as serialized)

| LMDB key | Value | Citation |
|---|---|---|
| `B0 ‖ "control_db"` (ASCII, no length) | `WalletHeader_Control::serialize()` (varint-prefixed packet, §6) | key W/WalletFileInterface.cpp:294-297, W/WalletHeader.cpp:55-65; write :527-529 |
| `09 00 00 00` (WALLET_SEED_KEY=9 as u32LE) | `EncryptedSeed::serialize()` (packet), seed type `Raw` | W/WalletFileInterface.cpp:508-524; W/WalletHeader.h:24 |
| `C0 ‖ masterEncryptionKeyId(16)` | `EncryptionKey::serialize()` (packet) | W/DecryptedDataContainer.cpp:615-622, 660-667; prefix W/DecryptedDataContainer.h:21 |
| `C1 ‖ kdfId(32)` | `KeyDerivationFunction_Romix::serialize()` (packet). Always written, even without passphrase. Passthrough KDF never stored. | W/DecryptedDataContainer.cpp:669-693; W/WalletFileInterface.cpp:494-496; KDF_PREFIX W/WalletIdTypes.h:15 |
| `CC ‖ keyId(16)` | transient backup of an EncryptionKey during passphrase change; deleted afterwards; ignored on load (switch has no default) | W/DecryptedDataContainer.cpp:942-967, 733-754; W/DecryptedDataContainer.h:22 |

`readFromDisk` seeks to `0xC0` and iterates to the end, dispatching on first key byte (W/DecryptedDataContainer.cpp:712-757). For `C1` entries the key suffix must equal the recomputed KDF id (:747-749).

#### 1.5 Records in the `WalletHeader` DB (plaintext keys/values inside EncryptedDB)

| Data key | Value | Citation |
|---|---|---|
| `B0 ‖ walletId` | WalletHeader serialization (packet) | W/WalletFileInterface.cpp:538-545, 146-180 |
| `A0 00 00 00` (MASTERID_KEY) | `varint(len) ‖ masterId` | W/Wallets.cpp:225-233; read :180-188 |
| `A1 00 00 00` (MAINWALLET_KEY) | `varint(len) ‖ walletId` | W/Wallets.cpp:146-158; read :161-177 |

`loadHeaders` seeks to `0xB0` and iterates to the end, stripping the varint packet length and deserializing each header; stops (break) on first deserialization exception (W/WalletFileInterface.cpp:146-180). Headers with `shouldLoad()==false` (Subwallet) are skipped (:170-172; W/WalletHeader.cpp:413-416).

#### 1.6 Records in a per-wallet DB (partial — only those touched by this research)

| Data key | Value | Citation |
|---|---|---|
| `07 00 00 00` ROOTASSET_KEY | root AssetEntry serialization | W/Wallets.cpp:1551-1558, 266-274 |
| `08 00 00 00` MAIN_ACCOUNT_KEY | `AddressAccountId::serializeValue` = `varint(4) ‖ i32BE` (NOT packet-wrapped; read raw) | W/Wallets.cpp:130-137, 253-259; W/WalletIdTypes.cpp:119-121, 187-194 |
| `09 00 00 00` WALLET_SEED_KEY | `EncryptedSeed` (packet), encrypted with the wallet master key | W/Wallets.cpp:1537-1549, 277-292 |
| `31 00 00 00` / `32 00 00 00` | label / description (packet, read via `getDataRefForKey`) | W/WalletHeader.h:26-27; W/Wallets.cpp:294-312 |
| `C0 ‖ keyId` / `C1 ‖ kdfId` | wallet (private-key) EncryptionKey / KDF, same formats as in control_db | W/Wallets.cpp:1519-1535, 314-315 |
| `8A ‖ AssetId(12)` | asset entries (contain `Asset_PrivateKey`, §5) | W/Assets.h:21; W/Assets.cpp:70 |
| `D0…`, `E1…E4`, `F1…` | address accounts, asset accounts, meta accounts | W/Accounts/AddressAccounts.h:26; W/Accounts/AssetAccounts.h:22-25; W/Accounts/MetaAccounts.h:20 |

---

### 2. Control layer

#### 2.1 What the control passphrase is
* "encrypts/unlocks all data in the wallet" (`setCtrlPassObj`) vs. "encrypts/unlocks private keys" (`setPrivPassObj`) (W/IOHeader.h:46-51). The control passphrase protects the control master key, which protects the control seed, from which all EncryptedDB keys are derived (§2.4).

#### 2.2 `setupControlDB` (W/WalletFileInterface.cpp:467-535)
1. Open `control_db` (:470).
2. New `WalletHeader_Control`, `walletID_ = "control_db"` (:473-474).
3. `initWalletHeaderObject(header, ctrlParams)`; if `setCtrlPassObj.get()` throws, logs "No control passphrase provided!" and uses `Params{250ms, 0, {}}` (empty passphrase) (:476-484).
4. Build a `DecryptedDataContainer` with the header's default key / ids, add the master `EncryptionKey` and the Romix KDF (:487-496).
5. Generate a **32-byte random control seed** (`generateRandomStrong(32)`), encrypt it with a copy of `mks.cipher_` (passthrough KDF id, key id = master key id, fresh IV), wrap as `EncryptedSeed(cipherData, SeedType::Raw)` (:507-516).
6. Raw-write seed at `u32LE(9)`, header at `B0‖"control_db"`, then `updateOnDisk` writes `C0‖masterKeyId` and `C1‖kdfId` (:519-532).

#### 2.3 `initWalletHeaderObject` (W/WalletFileInterface.cpp:344-464) — shared by control and per-wallet headers
* `masterKey = generateRandomStrong(32)`; derived with passthrough KDF; `masterEncryptionKeyId = computeId(masterKey)` (:363-368).
* Always creates `KeyDerivationFunction_Romix(params.unlockMs, params.memTargetMB)`; `header.defaultKdfId_ = kdf.getId()` (:374-376).
* `mks.cipher_ = Cipher_AES(passthroughKdfId, masterEncryptionKeyId)` — the cipher used to encrypt payloads with the master key (:381-384).
* `header.defaultEncryptionKey_ = generateRandomStrong(32)` (stored **in clear** in the header); `defaultEncryptionKeyId_ = computeId(defaultKey)` under passthrough (:389-399).
* If passphrase non-empty: `topKey = Romix(passphrase)`; `topKeyId = computeId(topKey)`; cipher `Cipher_AES(romixKdfId, topKeyId)` (random IV); `encrMaster = AES-CBC(masterKey, topKey, iv)` (:405-428).
* Else: cipher `Cipher_AES(passthroughKdfId, defaultEncryptionKeyId)` (fresh IV via `getCopy`), `encrMaster = AES-CBC(masterKey, defaultKey, iv)` (:432-453).
* `header.masterEncryptionKeyId_ = masterEncryptionKeyId` (:431, :456).
* `header.controlSalt_ = generateRandomStrong(32)` (:462).

#### 2.4 Opening: `setupEnv` (W/WalletFileInterface.cpp:68-129) and per-DB key derivation
1. Open env, open `control_db`, load control header (:80-88).
2. Load DecryptedDataContainer from control_db (C0/C1 records) and the control seed (:91-94, 308-341).
3. Lock container with the user unlock lambda; `rootEncrKey = decrypt(controlSeed)` (32 bytes) (:103-105).
4. Open the `WalletHeader` DB with a temp header whose `controlSalt_ = controlHeader.controlSalt_` (:108-114).
5. Load headers, then open each `<walletId>` DB with **its own header's** `controlSalt_` and the same `rootEncrKey` (:117-125; DBInterface ctor W/EncryptedDB.cpp:117-125; W/WalletFileInterface.cpp:220-240).

Per-DB key schedule (W/EncryptedDB.cpp:154-182):
```
saltedRoot   = HMAC-SHA256(key = controlSalt_of_db, msg = rootEncrKey)          // :161
for counter i (u32):
  h_i        = HMAC-SHA512(key = 4 bytes of i in HOST order (LE), msg = saltedRoot) // :166-167
  priv_i     = h_i[0..32]   (must be a valid secp256k1 scalar, else throw)       // :171, 175-177
  mac_i      = h_i[32..64]                                                       // :172
  pub_i      = compressed pubkey(priv_i) (33 B)                                  // :309-310, 324
```
Note: the HMAC key is `(uint8_t*)&hmacKeyInt, 4` — native byte order, not an explicit endianness (W/EncryptedDB.cpp:166).

#### 2.5 Missing / empty control passphrase
* Not "no encryption": the control master key is encrypted under the **default key**, which is 32 random bytes stored in plaintext in the control header (W/WalletFileInterface.cpp:389-390, 432-453; W/WalletHeader.cpp:84-85). Log message says "The public data in this wallet will not be encrypted" (W/WalletFileInterface.cpp:480-481). Effectively anybody can decrypt.
* `DecryptedDataContainer::initAfterLock` pre-inserts the default key into the clear-key map (W/DecryptedDataContainer.cpp:55-68), so `populateEncryptionKey` finds the key needed to decrypt the master key without calling `promptPassphrase` (W/DecryptedDataContainer.cpp:429-443, 469-518, 520-528).
* `Passphrase::SetNew()` default params: type `Invalid`, `unlockMs 0`, empty passphrase (W/GetPassphrase.cpp:24-26, 44-47); `get()` returns them without throwing (:78-91). So the "catch → 250ms" path at W/WalletFileInterface.cpp:479-484 is only hit when `get()` throws (null params and null lambda, or a rejected lambda) (W/GetPassphrase.cpp:80-88).
* Test: a file created with an empty control passphrase opens with an unlock lambda that throws if called, in <50 ms (gtest/WalletTests.cpp:3292-3330).
* Change/erase: `changeControlPassphrase` → `encryptEncryptionKey` (W/WalletFileInterface.cpp:712-757); `eraseControlPassphrase` → `eraseEncryptionKey`, which re-encrypts under the default key (passthrough) if it removes the last cipher (W/DecryptedDataContainer.cpp:1056-1078). Both then compact the file (W/WalletFileInterface.cpp:756, 790).

---

### 3. EncryptedDB record format (encryption version 1)

#### 3.1 LMDB keys are counters (key hiding)
* Every LMDB key in an EncryptedDB is a **4-byte big-endian counter** (`dbKeyCounter_++`, `WRITE_UINT32_BE`) (W/EncryptedDB.cpp:102-106). The real ("data") key is stored inside the encrypted value. Keys of other sizes → "invalid dbkey" (:234-236); dbKey ≥ `0x10000000` → "invalid dbkey" (:243-248).
* On load, keys are iterated in LMDB order (ascending BE = write order) (:227-283). The whole DB is decrypted into RAM (W/WalletFileInterface.cpp:233-236; W/EncryptedDB.cpp:154). Counter resumes at `lastKey+1` (:291).
* Overwrite/delete never reuses a dbKey: the old LMDB entry is deleted, an "erased" placeholder packet is written under a new dbKey, and (for overwrite) the new value under another new dbKey (W/WalletFileInterface.cpp:999-1051). After a commit with deletions the file is compacted (mdb_env_copy2 MDB_CP_COMPACT + zero-wipe of the old file) (W/WalletFileInterface.cpp:1061-1072, 794-881; lmdbpp/lmdbpp.cpp:621-631).

#### 3.2 Value byte layout (`createDataPacket`, W/EncryptedDB.cpp:329-400; `readDataPacket` :403-487)

On disk (LMDB value):
| Offset | Size | Field |
|---|---|---|
| 0 | 33 | `R` — ephemeral compressed secp256k1 pubkey (`localPubKey`) (:365-369, 388; read :420) |
| 33 | 16 | IV (fortuna random, AES block size) (:380-381, 389; read :431-432) |
| 49 | rest | AES-256-CBC ciphertext (:384-385, 390) |

Encryption key: `S = ECDH(pub_i, r)` serialized compressed (33 B) → `aesKey = Hash256(S)` (double SHA-256) (:372-376). Decrypt side: `S = priv_i · R`, same hash (:423-427). A **fresh ephemeral key per entry** (`createNewPrivateKey`) (:365).

Plaintext (before AES):
| Field | Encoding |
|---|---|
| `mac` | 32 bytes |
| `dataKeyLen` | varint |
| `dataKey` | bytes |
| `valueLen` | varint |
| `value` | bytes |

(:342-359; parse :443-462; trailing bytes → "loose data entry" :460-462.)

MAC: `mac = HMAC-SHA256(key = mac_i, msg = varint(len k) ‖ k ‖ varint(len v) ‖ v ‖ dbKey(4 BE bytes))` — covers the whole plaintext payload plus the LMDB key, so entries cannot be moved between keys (:349-354; verify :464-478). MAC-then-encrypt (MAC inside the ciphertext). Padding: AES-CBC PKCS#5/7 (§0). Comment "pad payload to modulo blocksize" at :361 has no code beyond AES's own padding.

#### 3.3 Meta packets & key rotation
A packet with an **empty data key** is meta (:264-274):
* **Erasure placeholder**: value = `"erased"` (6 raw ASCII bytes) ‖ `varint(4)` ‖ erased dbKey (4 BE) (W/WalletFileInterface.cpp:1008-1018). On load, the referenced dbKey must be a recorded gap; it is removed from the gap set (W/EncryptedDB.cpp:188-207). Any gap left unfilled at the end → "unfilled dbkey gaps!" (:286-288).
* **Key-cycle flag**: value = `"cycle"` (5 ASCII bytes) → counter `i += 1`, recompute `priv_i, mac_i` (:211-216).
* Any other empty-key packet → "empty data key" error (:269-271).

Rotation per session: every time a DB is opened, after reading all entries `loadAllEntries` **appends a `"cycle"` packet** (encrypted with the current key `i`) at the next dbKey, then switches to key `i+1` for all writes in this session (:297-325). So each open mutates the file. For a fresh DB, `prevDbKey=-1` → counter 0 (:229, 291) and `computeKeyPair(0)` (:181-182) precede the flag write (:304-316), so dbKey 0 is the cycle flag under key 0 and real data starts under key 1. A reader must process entries strictly in dbKey order, decrypting each with the current `i`.

There is no per-entry DH ratchet beyond the ephemeral ECIES key; no key derivation from dbKey.

#### 3.4 Encryption version
* Only `0x00000001` is supported in both directions (W/EncryptedDB.cpp:336-397, 411-484).
* `setupEnv` takes `encryptionVersion_` from a **freshly constructed** `WalletHeader_Control` (= `ENCRYPTION_TOPLAYER_VERSION` = 1) rather than from the header loaded from disk (W/WalletFileInterface.cpp:109-113; W/WalletHeader.cpp:291-298; W/WalletHeader.h:39). Also `serializeVersion` writes the constant, not the member (W/WalletHeader.cpp:313). So the on-disk value is parsed but effectively ignored.

---

### 4. KDF

#### 4.1 Algorithm (`KdfRomix::DeriveKey_OneIter`, W/KDF.cpp:148-214)
```
X0      = SHA512(password ‖ salt)                         // :151, 162
V[0]    = X0; V[j+1] = SHA512(V[j])  for table of memBytes/64 entries   // :154-172
X       = V[last]                                          // :176
seqCount = memBytes / 64                                   // :130 / :78
repeat seqCount/2 times:                                   // :193-194
  idx = u32(X[60..64]) (native order, LE) mod seqCount     // :196
  X   = SHA512(X xor V[idx])                               // :199-208
return X[0..32]                                            // :213, kdfOutputBytes=32 :27
DeriveKey: key = pw; repeat numIterations: key = OneIter(key)   // :217-224
```
Hash = SHA-512 (W/KDF.cpp:25-26). Output 32 bytes. The index read is `*(uint32_t*)` (native order) (:196).
Byte-exactness note: the table is `resize(memBytes)` and the hash chain fills offsets `0, 64, … < memBytes-64` (:154, 166-172); X is read from offset `memBytes-64` (:176), and `seqCount = memBytes/64` (integer division). In practice memBytes = 1024·2^k (:73-87) so these coincide, but a deserialized `memTargetBytes` is an arbitrary u32 (:267) — mirror the C++ layout exactly, do not round.

#### 4.2 Parameter selection (`computeKdfParams`, W/KDF.cpp:61-123)
* `salt = generateRandomStrong(32)` (:67).
* Memory starts at `max(minMem, 1024)` capped at `256 MiB` (W/KDF.h:31-32; W/KDF.cpp:73-74), doubles until one iteration takes ≥ `target/4` or memory ≥ 256 MiB (:77-87).
* Iterations: time `numTest` (doubling) iterations until ≥100 ms; `perIter = ms/numTest`; `iters = target/(perIter+1)`; `iters = iters<1 ? 1 : iters+1` (:95-114).
* `minMem` = `memTargetMB * 1024 * 1024` (W/KDF.cpp:330). Callers: control default `250ms, 0 MB` (W/WalletFileInterface.cpp:482); target from `Passphrase::Params.unlockMs/memTargetMB` (W/WalletFileInterface.cpp:374-375).

#### 4.3 Serialized form (`KeyDerivationFunction_Romix::serialize`, W/KDF.cpp:345-360; parse :241-290)
```
varint(totalLen)
u32LE version = 0x00000001          (KDF_ROMIX_VERSION, :16)
u16LE prefix  = 0xC100  → bytes 00 C1   (KDF_ROMIX_PREFIX, :17)
u32LE iterations
u32LE memTargetBytes
varint(saltLen) ‖ salt (32 bytes in practice)
```
Stored under LMDB/data key `C1 ‖ kdfId` (W/WalletIdTypes.cpp:785-790).

KDF id: `kdfId = Hash256(salt ‖ u32LE iterations ‖ u32LE memTargetBytes)` (32 bytes) (W/KDF.cpp:312-323). Passthrough KDF id = ASCII `"PASSTHROUGH_SENTINEL"` (20 bytes), never serialized (W/KDF.h:84; W/KDF.cpp:422-455).

#### 4.4 Relation to classic Armory 1.35 ROMix
* Design comment: "variation of Colin Percival's ROMix" with T/2..T target (W/KDF.h:41-46); "lookups = seqCount/2" (W/KDF.cpp:187-193).
* The **same `KdfRomix` class** is used to decrypt legacy 1.35 wallet roots on import: `KdfRomix{kdfMem_, kdfIter_, kdfSalt_}.DeriveKey(passphrase)` then `AES::decryptCFB` (BridgeAPI/Wallets/Loader.cpp:494-500), with params parsed from the 1.35 file as `u64 mem, u32 iter, 32-byte salt` (BridgeAPI/Wallets/Loader.cpp:368-370). That is direct evidence the algorithm is byte-compatible with 1.35 ROMix (SHA-512, sequential table, seqCount/2 lookups, 32-byte output, salt appended).
* Differences: memory ceiling now 256 MiB (comment says it used to be 32 MB, W/KDF.h:20-29); mem serialized as u32 here vs u64 in 1.35; new-format private keys use AES-CBC, legacy used AES-CFB (Loader.cpp:499).

---

### 5. Private-key / asset encryption structures

#### 5.1 Constants (W/AssetEncryption.h:15-24)
`CIPHER_BYTE 0xB2`, `PRIVKEY_BYTE 0x82`, `ENCRYPTIONKEY_BYTE 0x83`, `CIPHER_DATA_VERSION 1`, `ENCRYPTION_KEY_VERSION 1`, `HMAC_KEY_ENCRYPTIONKEYS "EncyrptionKey"` (sic). `CipherType_AES = 0`, `CipherType_Serpent = 1` (only AES implemented, W/AssetEncryption.cpp:62-77, 130-141). Also `WALLET_SEED_BYTE 0x84` (W/Seeds/Seeds.cpp:32).

#### 5.2 Cipher (W/AssetEncryption.cpp:165-182; parse :105-149)
```
u32LE version = 1
u8    0xB2
u8    cipherType (0 = AES)
varint(len) ‖ kdfId          (32-byte Hash256 id or "PASSTHROUGH_SENTINEL")
varint(len) ‖ encryptionKeyId (16 bytes)
varint(len) ‖ iv              (16 bytes; must equal block size, :48-50)
```
A new random IV for every Cipher object (`getCopy` regenerates IV) (W/AssetEncryption.cpp:32-38, 79-82, 185-193).
Encrypt: `AES-256-CBC(data, derivedKey[kdfId], iv)` (:196-204). Decrypt: `AES-256-CBC-decrypt(ct, key, iv)` (:215-219).

#### 5.3 CipherData (W/AssetEncryption.cpp:262-311)
```
u32LE version = 1
varint(len) ‖ cipherText
varint(len) ‖ Cipher (as 5.2)    (the len is checked but Cipher is parsed from the same reader)
```

#### 5.4 EncryptionKey (W/AssetEncryption.cpp:380-462)
```
varint(totalLen)                 (packet)
u32LE version = 1
u8    0x83
varint(16) ‖ keyId               (id of the *inner* key, e.g. masterEncryptionKeyId)
varint(n)                        (number of CipherData)
n × [ varint(len) ‖ CipherData ] (one per outer key/passphrase; map key = cipher.encryptionKeyId)
```
Multiple passphrases = multiple CipherData entries, each with its own outer key id/KDF/IV (W/AssetEncryption.h:177-185; add/replace W/DecryptedDataContainer.cpp:919-937).

#### 5.5 Key ids (`ClearTextEncryptionKey::computeId`, W/AssetEncryption.cpp:493-503)
`id = last16( HMAC-SHA256(key = Hash256(P), msg = "EncyrptionKey") )` where `P = uncompressed (65-byte) pubkey of scalar Hash256(derivedKey)`. (`computePublicKey` default uncompressed, Utils/Cryptography.h:174; `computeDataId` Utils/BtcUtils.cpp:1044-1064.) `derivedKey` = KDF output (Romix) or the raw key (passthrough) (W/AssetEncryption.cpp:484-491, 517-525).

#### 5.6 Asset_PrivateKey (W/Assets.cpp:995-1010; parse :1086-1140)
```
varint(totalLen)
u32LE version = 2  (1 and 2 parse identically in deserialize; v1 "old" form has a 4-byte i32 id, :1012-1084)
u8    0x82
varint(12) ‖ AssetId  (3 × i32 BE: addressAccount, assetAccount, assetKey; W/WalletIdTypes.cpp:457-470, 606-621)
varint(len) ‖ CipherData
```
Selection between the two parsers: the AssetEntry parser tries `deserialize` first and falls back to `deserializeOld` on `IdException`/`AssetException` (W/Assets.cpp:183-200); `AssetId(BinaryData)` throws `IdException` unless the id is 12 bytes (W/WalletIdTypes.cpp:448-454).
Private keys / roots / seeds are encrypted with a `Cipher_AES(passthroughKdfId, masterEncryptionKeyId)` (W/Wallets.cpp:106-108, 1449-1461).

#### 5.7 EncryptedSeed (W/Seeds/Seeds.cpp:94-109; parse :128-190)
```
varint(totalLen)
u32LE version = 2
u8    0x84
i32LE seedType   (ArmoryLegacy 0, BIP32_Structured 1, BIP39 8, BIP32_Virgin 15, BIP32_base58Root 16, ArmoryLegacyPublic 32, Raw INT32_MAX-1; W/Seeds/Seeds.h:46-97)
varint(len) ‖ CipherData
```
(v1: no seedType field, implies `Raw`, :148-165.) Asset id is the fixed dummy `(0x5EED,0xDEE5,0x5EED)` (:79).

#### 5.8 Unlock recipe (reader's view) — DecryptedDataContainer
1. Load `EncryptionKey` at `C0‖masterEncryptionKeyId` and all KDFs at `C1‖…` (W/DecryptedDataContainer.cpp:712-757).
2. For each CipherData of the master key:
   * If `cipher.kdfId == "PASSTHROUGH_SENTINEL"` and `cipher.encryptionKeyId == header.defaultEncryptionKeyId`: outer key = `header.defaultEncryptionKey` (no user input) (W/DecryptedDataContainer.cpp:55-68, 429-443).
   * Else (passphrase): `k = Romix_{kdfId}(passphrase)`; accept iff `computeId(k) == cipher.encryptionKeyId` (W/DecryptedDataContainer.cpp:571-612). Wrong passphrases loop back to the prompt.
3. `masterKey = AES-256-CBC-decrypt(cipherData.cipherText, k, cipher.iv)` (32 bytes) (W/DecryptedDataContainer.cpp:495-505). Optional check: `computeId(masterKey) == masterEncryptionKeyId` (passthrough) (:530-533).
4. Asset/seed: its cipher has `kdfId = passthrough`, `encryptionKeyId = masterEncryptionKeyId`; `clear = AES-256-CBC-decrypt(ct, masterKey, iv)` (W/DecryptedDataContainer.cpp:322-342; W/AssetEncryption.cpp:589-597).
5. `isMasterKeyEncrypted` = no CipherData uses the passthrough KDF (W/DecryptedDataContainer.cpp:143-166).

The same two-level scheme exists twice: control (control passphrase → control master → control seed → EncryptedDB keys) and per wallet (private passphrase → wallet master key → private keys/seed), each with its own default key in its header (W/Wallets.cpp:38-58, 1426-1446, 1519-1535).

---

### 6. WalletHeader types, serialization, versioning

#### 6.1 Constants
* Keys (u32LE): `WALLETTYPE_KEY 1, PARENTID_KEY 2, WALLETID_KEY 3, ROOTASSET_KEY 7, MAIN_ACCOUNT_KEY 8, WALLET_SEED_KEY 9, WALLET_LABEL_KEY 0x31, WALLET_DESCR_KEY 0x32, MASTERID_KEY 0xA0, MAINWALLET_KEY 0xA1`; `WALLETHEADER_PREFIX 0xB0` (W/WalletHeader.h:19-32).
* `VERSION_MAJOR 3, VERSION_MINOR 0, VERSION_REVISION 0, ENCRYPTION_TOPLAYER_VERSION 1` (W/WalletHeader.h:36-39).
* `HEADER_VERSION 1, HEADER_ENCRYPTIONKEY_VERSION 1, HEADER_SALT_VERSION 1, WALLETHEADER_SINGLE_VERSION 2, WALLETHEADER_MULTISIG_VERSION 2, WALLETHEADER_SUBWALLET_VERSION 1, WALLETHEADER_CONTROL_VERSION 1, WALLETHEADER_CUSTOM_VERSION 1` (W/WalletHeader.cpp:15-24).
* Header type enum: `Single 0, Multisig 1, Subwallet 2, Control 3, Custom 4` (W/WalletHeader.h:63-70).

#### 6.2 Key: `B0 ‖ walletId` (raw ASCII, no length) (W/WalletHeader.cpp:55-65); walletId is recovered from the key remainder (:162, 284-285).

#### 6.3 Value layouts (all wrapped as `varint(len) ‖ body`)

Common sub-blocks:
* EncryptionKey block (W/WalletHeader.cpp:78-120):
  `u32LE 1 ‖ varint‖defaultEncryptionKeyId(16) ‖ varint‖defaultEncryptionKey(32) ‖ varint‖defaultKdfId(32) ‖ varint‖masterEncryptionKeyId(16)`
* Salt block (:123-147): `u32LE 1 ‖ varint‖controlSalt(32)`

| Type | Body | Citation |
|---|---|---|
| Control | `u32LE 1 (ver) ‖ u32LE 3 (type) ‖ [u32LE 1 ‖ u8 major ‖ u16LE minor ‖ u16LE revision ‖ u32LE encryptionVersion] ‖ EncKeyBlock ‖ SaltBlock` | W/WalletHeader.cpp:337-350, 306-334, 243-262 |
| Single v2 | `u32LE 2 ‖ u32LE 0 ‖ magicBytes(4) ‖ EncKeyBlock ‖ SaltBlock` (v1: no magic, mainnet assumed) | :364-377, 171-197 |
| Multisig v2 | `u32LE 2 ‖ u32LE 1 ‖ magicBytes(4) ‖ EncKeyBlock ‖ SaltBlock` (v1 as above) | :391-404, 215-241 |
| Custom | `u32LE 1 ‖ u32LE 4` | :440-450, 264-278 |
| Subwallet | serializer writes `u32LE 1 ‖ varint(4) ‖ u32LE 2` with **no outer varint wrapper**, which `loadHeaders` would reject; apparently never written — unverified | :419-426; W/WalletFileInterface.cpp:159-164 |

Note: header deserialization reads `version` *before* `type`, matching the serializers (W/WalletHeader.cpp:164-166).

#### 6.4 Versioning / upgrades
* Format versions are per-structure u32 version fields (headers, cipher, cipherdata, encryption key, KDF, seed v1/v2, privkey v1/v2). Backward parsing paths exist for Single/Multisig v1 (no magic bytes), EncryptedSeed v1, Asset_PrivateKey v1 (cited above).
* Control header major/minor/revision are parsed but nothing in the focus files branches on them (W/WalletHeader.cpp:317-334). `encryptionVersion` effectively fixed at 1 (§3.4). No upgrade/migration path for the EncryptedDB layer found in the focus files.

---

### 7. Watching-only wallets & no-input opening

* WO definition at runtime: `root_ == nullptr || !root_->hasPrivateKey()` (W/Wallets.cpp:2093-2099).
* `forkWatchingOnly`: opens the source with its unlock params, exports public data, creates a new file with `woCtrlPassObj` as control passphrase, and builds the wallet header with `Passphrase::Params{}` (empty → default key path). The returned `MasterKeyStruct` is discarded, so **no wallet master EncryptionKey/KDF is written** to the WO wallet DB (W/Wallets.cpp:911-944, 2351-2393).
* `createFromPublicSeed` / `createBlank` → `initWalletDbWithPubRoot`, which (oddly) passes the *control* params to `initWalletHeaderObject` for the wallet header and also discards the master key struct (W/Wallets.cpp:1351-1414, 1602-1612).
* Data in WO files is still protected only by the control layer; with an empty control passphrase the file opens with no user input (§2.5; gtest/WalletTests.cpp:3292-3330). With a non-empty control passphrase and an empty/absent unlock lambda, opening fails with "empty passphrase lambda" (W/DecryptedDataContainer.cpp:584-586; gtest/WalletTests.cpp:3247-3257).
* Prompt count on open: one control passphrase prompt via `lockControlContainer(params.unlockFunc)` when encrypted (W/WalletFileInterface.cpp:96-105). Private-key passphrase is only prompted when a private asset is decrypted.

---

### Reader algorithm (summary)

1. `mdb_env_open(file, MDB_NOSUBDIR|MDB_RDONLY…)` with maxdbs ≥ number of named DBs (note: the real implementation opens read-write and appends a cycle flag to each EncryptedDB on every open — a read-only reader need not do that).
2. Raw-read `control_db`: header at `B0‖"control_db"` (strip varint), seed at `09000000`, master key at `C0‖masterKeyId`, KDF at `C1‖defaultKdfId`.
3. Unlock master (default key or Romix(passphrase)), decrypt seed → `rootEncrKey` (32 B).
4. For DB `WalletHeader` (salt = control header salt) and each `<walletId>` (salt from its header): derive `saltedRoot`, iterate entries in key order with counter `i=0`, ECIES-decrypt (33 B R ‖ 16 B IV ‖ CBC ct; key = SHA256d(compressed(priv_i·R))), verify HMAC-SHA256(mac_i, payload‖dbKeyBE), handle `"cycle"` (i++) and `"erased"` meta packets, enforce gap rules.
5. In each wallet DB, load `C0/C1` and unlock the wallet master key with the private passphrase (or that header's default key) to decrypt `0x82` private keys / `0x84` seed.

---

### Open questions / unverified
1. AES-CBC padding implementation (libbtc `aes256_cbc.c`) is not in this clone; PKCS#5/7 inferred from comment and size math only (Utils/Cryptography.cpp:237-258).
2. `WalletHeader_Subwallet::serialize` lacks the varint packet wrapper (W/WalletHeader.cpp:419-426); whether it is ever written is unverified.
3. HMAC counter key and ROMix index use host byte order (W/EncryptedDB.cpp:166; W/KDF.cpp:196) — files written on a big-endian host would differ; assumed LE.
4. `encryptionVersion` on disk is ignored on load (W/WalletFileInterface.cpp:109-113); intent unclear.
5. Exact AssetEntry / account / meta-account serializations (keys 0x8A, 0xD0, 0xE1-0xE4, 0xF1) were not researched beyond the prefixes.
6. `MDB_NOSUBDIR` lock-file naming (`<path>-lock`) is standard LMDB behaviour, not visible in this repo.
7. HMAC argument order (key first) rests on parameter names at Utils/BtcUtils.cpp:80-89, 240-254 and the call into libbtc `hmac_sha256/hmac_sha512` (Utils/Cryptography.cpp:742-761); libbtc's signature is not in the clone — standard order assumed, unverified here.

---

## Part B — goatpig Armory `dev` ("0.97") wallet model, as seen by an importer

Source: `/home/user/goatpig/bitcoinarmory`, commit `d0294d5913c8c272fbc89ac14c7623dec5ea1404` (2026-05-20).
All paths below are relative to that tree. `W/` = `cppForSwig/Wallets/`. "unverified" means the code needed to confirm the claim is not in the shallow clone, or I did not trace it.

The storage and encryption layer (LMDB sub-DBs, control/master keys, KDF, cipher) is left out on purpose. This document covers what the decrypted records mean.

---

### 0. Object hierarchy

```
WalletDBInterface (one LMDB file)
 └─ AssetWallet_Single  (sub-DB named after walletID; W/WalletHeader.cpp:50-52)
     ├─ root_          ROOTASSET_KEY 0x00000007   AssetEntry_ArmoryLegacyRoot | AssetEntry_BIP32Root  (W/Wallets.cpp:262-275)
     ├─ seed_          WALLET_SEED_KEY 0x00000009 EncryptedSeed (wraps a serialized ClearTextSeed)        (W/Wallets.cpp:277-292)
     ├─ label/descr    WALLET_LABEL_KEY 0x31 / WALLET_DESCR_KEY 0x32                                      (W/WalletHeader.h:26-27, W/Wallets.cpp:294-312)
     ├─ main account   MAIN_ACCOUNT_KEY 0x00000008 -> AddressAccountId                                    (W/Wallets.cpp:251-260, 127-138)
     ├─ AddressAccount[]   key 0xD0|AddressAccountId                                                      (W/Accounts/AddressAccounts.h:26)
     │    ├─ outer/inner AssetAccountId, address-type set, default type                                   (AddressAccounts.cpp:358-439)
     │    ├─ AssetAccount[] key 0xE1|AssetAccountId : type, DerivationScheme                              (AssetAccounts.cpp:139-183)
     │    │    ├─ assets   key 0x8A|AssetId (root has index -1)                                           (AssetAccounts.cpp:276-317)
     │    │    ├─ count    key 0xE2|AssetAccountId                                                        (AssetAccounts.cpp:222-235)
     │    │    └─ highest used index  key 0xE4|AssetAccountId (int32), legacy 0xE3 (varint)               (AssetAccounts.cpp:237-273, 594-610)
     │    └─ per-address type overrides key 0xD8|AssetId -> uint32 AddressEntryType                        (AddressAccounts.cpp:528-549, 1057-1111)
     └─ MetaDataAccount[]  key 0xF1|id  (Comments id 0xC0, AuthPeers id 0xC1)                             (W/Accounts/MetaAccounts.h:18-20)
          └─ comment records key 0x90|accountId|index(BE)                                                (W/Assets.cpp:1788-1799)
```

ID types (W/WalletIdTypes.h:40-173): `AddressAccountId` (int32), `AssetAccountId` (= AddressAccountId + int32), and `AssetId` (= AssetAccountId + int32 asset index). The root sentinel is `-1` (`rootAccountId`/`rootAssetId`, W/WalletIdTypes.h:42-43; `getRootAssetId()` = (-1,-1,-1), W/WalletIdTypes.cpp:600-603).

---

### 1. Wallet kinds and wallet ID

#### Kinds
- `AssetWallet_Single` is the only working wallet kind (W/Wallets.h:279-387). It is loaded when the header type is `WalletHeaderType_Single` (W/Wallets.cpp:810-820).
- `AssetWallet_Multisig` (W/Wallets.h:390-418) is effectively a stub. `createFromWallets` is declared (W/Wallets.h:413-416), but a grep over all `.cpp` in cppForSwig finds no definition. `readFromFile` sets `unsigned n = 0` and then loops `for i<n`, so it never loads a sub-wallet (W/Wallets.cpp:2413-2450, `n = 0` at :2438). Importer: ignore it, and treat a multisig file as unsupported.
- Other header types exist (`Subwallet`, `Control`, `Custom`; W/WalletHeader.h:63-69). They are not wallets for our purpose. `AuthorizedPeers` is a separate peer-key DB.
- Whether a wallet is watching-only depends on whether the root holds a private key (`isWatchingOnly`, W/Wallets.cpp:2093).

#### Wallet ID (`walletID`)
`generateWalletId(pubkey, chaincode, seedType)` (W/WalletIdTypes.cpp:835-867) works like this:
1. It builds a `DerivationScheme_ArmoryLegacy(chaincode)` and a root `AssetEntry_Single` with id (-1,-1,-1) (:848-855).
2. It runs the Armory legacy chain from that root `(int)sType + 1` times and keeps the last key (`extendPublicChain(root, 0, (int)sType)`; the legacy scheme ignores `start` and loops from root index -1 to `end`; :64-76 and W/DerivationScheme.cpp:195-224).
3. It takes `computeID(uncompressedPubKey)` = `reverse( pubkeyHashPrefix || hash160(pub65)[0:5] )` (6 bytes; :25-41), then base58-encodes the result (:865).

Number of chain steps for each seed type (`SeedType` values, W/Seeds/Seeds.h:46-97):

| SeedType | value | chain steps | key used |
|---|---|---|---|
| ArmoryLegacy | 0 | 1 | chain index 0 = first address, the same as classic 1.35 |
| ArmoryLegacyPublic | 32 | coerced to ArmoryLegacy (W/WalletIdTypes.cpp:48-62) | same as full wallet |
| BIP32_Structured | 1 | 2 | — |
| BIP39 | 8 | 9 | — |
| BIP32_Virgin | 15 | 16 | — |
| BIP32_base58Root | 16 | 17 | — |

- For legacy seeds the chain input is the root pubkey and the chaincode. A deterministic 1.35c or Armory200 chaincode is recomputed if it is empty (W/Seeds/Seeds.cpp:440-448).
- For BIP32 seeds the input is the BIP32 master pubkey and the master chaincode (W/Seeds/Seeds.cpp:654-659). The legacy chain steps use the uncompressed form (W/DerivationScheme.cpp:205).
- **Comparison with classic Armory:** classic uses `base58( (ADDRBYTE + hash160(firstAddr.pub65)[:5])[::-1] )`, where firstAddr is the first chained key, chain index 0. This is the same as the ArmoryLegacy case. The migration code relies on it: it throws `"wallet id mismatch"` unless the new wallet ID equals the 6-byte ID read from the 1.35 file header (BridgeAPI/Wallets/Loader.cpp:334-337, 546-548). The gtest `WalletsTest.IDs` checks both the legacy and BIP32 forms (cppForSwig/gtest/WalletTests.cpp:4330-4380).

#### Master ID (`masterID`)
`generateMasterId(pubkey, chaincode)` = `base58(computeID(HMAC-SHA256(key = pubkey||chaincode, msg = "MetaEntry")))` (W/WalletIdTypes.cpp:870-883; argument order key, msg per Utils/BtcUtils.cpp:80-89). Watch for an asymmetry: `ClearTextSeed_Armory::computeMasterId` passes the raw `chaincode_` member (W/Seeds/Seeds.cpp:450-455). That member is **empty** for Armory200 and 1.35c (deterministic-chaincode) seeds (:412-416; Loader.cpp:531-535). `computeWalletId` substitutes the derived chaincode in that case, but `computeMasterId` does not. The master ID names the file and is checked on load (W/Wallets.cpp:180-200). It is not user-facing.

#### Where the IDs are stored
- The wallet ID is the sub-DB name (`WalletHeader::getDbName()` returns `walletID_`, W/WalletHeader.cpp:50-52). It is also written as the "main wallet" under `MAINWALLET_KEY 0xA1` in the header DB (W/Wallets.cpp:146-158) and in the header (W/Wallets.cpp:1428).
- The master ID sits under `MASTERID_KEY 0xA0` in the header DB (W/Wallets.cpp:180-188; W/WalletHeader.h:29-30).
- Multisig reads `WALLETID_KEY 0x03` (W/Wallets.cpp:2425) and a chain length (:2435).

---

### 2. Seeds (root material)

`ClearTextSeed` subclasses (W/Seeds/Seeds.h:124-280). The seed is kept **encrypted** under `WALLET_SEED_KEY` (W/Wallets.cpp:1537-1549) in addition to the root asset. The private root is also kept encrypted in the root asset (W/Wallets.cpp:1463-1513).

| Seed class | SeedType | Root material | Notes |
|---|---|---|---|
| `ClearTextSeed_Armory` | ArmoryLegacy (0) | 32-byte private root, optional 32-byte chaincode, `LegacyType` | A random 32-byte root with an empty chaincode means the chaincode is deterministic (W/Seeds/Seeds.cpp:412-423) |
| `ClearTextSeed_ArmoryPublic` | ArmoryLegacyPublic (32) | public root and chaincode | `deserialize` throws `"implement me!"` (Seeds.cpp:323-326), so only watching-only creation via `createFromPublicSeed` works |
| `ClearTextSeed_BIP32` | BIP32_Structured (1), BIP32_Virgin (15) | 32 random bytes **used directly as the BIP32 seed**: `BIP32_Node::initFromSeed(rawEntropy_)` (Seeds.cpp:669-676, 619-621). **No mnemonic exists.** | Structured gets BIP44/49/84 accounts; Virgin gets none (W/Wallets.cpp:1329-1343) |
| `ClearTextSeed_BIP32::fromBase58` | BIP32_base58Root (16) | an xprv string; the root node comes from it (Seeds.cpp:643-651) | `rawEntropy_` is random filler from the ctor (Seeds.cpp:619-621, 646-647). **Do not use it.** Serialized as the base58 string (Seeds.cpp:701-708) |
| `ClearTextSeed_BIP39` | BIP39 (8) | BIP39 **entropy** (default 32 bytes, so 24 words), dictionary `English_Trezor=1` | Seed = `mnemonic_to_seed(mnemonic_from_data(entropy), passphrase="")`, then `initFromSeed(seed64)` (Seeds.cpp:807-834). **The BIP39 passphrase is always empty.** |

`LegacyType` (Seeds.h:100-119): `Undefined=0`, `Armory135=12`, `Armory200=34`. It only selects the backup flavour (135a/c versus 200a). Derivation is identical.

#### ClearTextSeed serialization (the plaintext inside the EncryptedSeed)
`uint8 seedType | varint len | TLV...` (Seeds.cpp:271-283 and the serializers). Prefixes (Seeds.h:132-142):
- `0x66 LegacyType` (u8)
- `0x11 Root` (varint len + bytes)
- `0x12 PublicRoot`
- `0x22 Chaincode` (varint len, may be 0)
- `0x44 RawEntropy`
- `0x55 Dictionnary` (u32)
- `0x77 Base58Root`

Writers:
- Armory: Seeds.cpp:458-489
- ArmoryPublic: :584-615
- BIP32: :684-725
- BIP39: :848-872

The seed type is written as **u8** here (:275, :482) but as **int32** in the EncryptedSeed wrapper.

EncryptedSeed wrapper (Seeds.cpp:94-109, 128-205):
- Layout: `varint total | u32 version(2) | u8 0x84 | i32 seedType | varint len | CipherData`.
- Version 1 has no seedType field and is treated as `SeedType::Raw` (:148-165).
- Fixed AssetId is `(0x5EED,0xDEE5,0x5EED)` (:79).

#### Root asset (what can be derived without the seed record)
- `AssetEntry_ArmoryLegacyRoot`: v2 = `u8 legacyType, varint cc, pubkey(s), [privkey]` (W/Assets.cpp:844-870, deserialize :331-381). The **chaincode is always stored resolved** (derived if needed) (W/Wallets.cpp:1471-1485). v1 has no legacyType.
- `AssetEntry_BIP32Root`: v1/v2 = `u8 depth, u32 leafId, u32 parentFP, varint cc, [v2: u32 seedFP, varint n, u32 path[n]], pubkey(s), [privkey]` (W/Assets.cpp:456-489, 278-329). v1 roots have no seed fingerprint and no path.
- Fingerprint = first 4 bytes of **hash160**(compressed pubkey), read as a native uint32 (W/Assets.cpp:757-773). The header comment says hash256 (W/Assets.h:253-256). The comment is wrong; the code uses hash160.

#### Backups (W/Seeds/Backups.{h,cpp})
`BackupType` (Backups.h:55-91):

| BackupType | value | Content | Seed restored |
|---|---|---|---|
| Armory135a | 0 | Easy16 root (2 lines) + chaincode (2 lines), checksum hint 0 | ClearTextSeed_Armory, Armory135 (Backups.cpp:1391-1399) |
| Armory135c | 1 | Easy16 root only (2 lines), **hint 0** (Backups.cpp:436-438) | same |
| Armory200a | 3 | Easy16 legacy root, hint 3 | ClearTextSeed_Armory, Armory200 (:1401-1408) |
| Armory200b | 4 | Easy16 raw 32-byte BIP32 seed | BIP32_Structured (:1411-1417) |
| Armory200c | 5 | Easy16 raw BIP32 seed | BIP32_Virgin (:1419-1425) |
| Armory200d | 10 | Easy16 **BIP39 entropy** (not the words) (:1090-1104) | ClearTextSeed_BIP39 (:1427-1433) |
| BIP39 | 0xFFFF | English mnemonic (Backups.cpp:1137-1173) | BIP39; `mnemonic_to_bits`, entropy stripped of checksum (:1462-1492) |
| Base58 | 58 | xprv string (:1176-1190) | BIP32_base58Root (:1443-1459) |
| Raw / Invalid / Easy16_Unkonwn | — | — | — |

Easy16 format:
- Alphabet `asdfghjkwertuion` (Backups.cpp:53-59).
- 16-byte lines (EASY16_LINE_LENGTH, :26-28).
- 2-byte checksum = `hash256(line || hintByte)[0:2]`. With hint 0 (1.35), no byte is appended (:89-99, 36-44).
- On restore the hint is the backup type (`verifyChecksum` tries the eligible indexes, :101-111; :1372-1376).

So **Armory135a/c paper backups use the classic Easy16 format** (hint 0). The new formats are told apart only by the checksum hint byte. SecurePrint uses fixed IV/salt strings from the digits of pi and e and a 16 MiB KDF (:64-85, 789-851).

Watching-only backups exist **only for legacy roots**. `getWalletBackup(..., isPriv=false)` logs "public backups needs implemented for non legacy roots!" and returns null for anything else (Backups.cpp:1006-1016). The format is `Backup_Easy16Public` (pubroot + chaincode + backup id; Backups.cpp:1618-1656). BIP32 watching-only wallets have no paper form.

---

### 3. Accounts

#### AccountType enum (W/Accounts/AccountTypes.h:60-91)
`ArmoryLegacy=0, BIP32=1, BIP32_Salted=2, ECDH=3, Imports=4`. This is the in-memory enum. On disk an account is described by its AssetAccount `type` byte (`AssetAccountType` Plain=0, ECDH=1, Imports=2, ImportsWO=3; AccountTypes.h:52-58) together with the serialized DerivationScheme (AssetAccounts.cpp:151-165).

#### IDs and constants (AccountTypes.h:19-26)
- `ARMORY_LEGACY_ACCOUNTID 0xF6E10000`: fixed AddressAccountId of the legacy account (AccountTypes.cpp:84-85). Asset account key `ARMORY_LEGACY_ASSET_ACCOUNTID = 1` (:126-129).
- `IMPORTS_ACCOUNT_PRIV 0x1200` / `IMPORTS_ACCOUNT_PUB 0x1201`, asset account `IMPORTS_ACCOUNTID 0` (AccountTypes.cpp:548-561).
- `ECDH_ASSET_ACCOUNTID 0x20000000` (:521-524). The ECDH address-account ID = first 4 bytes (BE) of hash160(compressed root pub with `byte[0] ^= 3`) (:489-518).
- **BIP32 / Salted address-account ID** = first 4 bytes (BE int32) of `hash160( u32 seedFP(LE) || each path node (BE) || each address type (BE) || u32 defaultType(LE) || u8 isMain )` (AccountTypes.cpp:190-239). The paths include the 0/1 leaf nodes (the forked branches). Collisions with the legacy or imports IDs throw an error. The ID therefore depends on the address-type set and the main flag, so it is not a pure path hash. Read the IDs from the file; do not try to recompute them.
- BIP32 asset account key = **last path node** (AddressAccounts.cpp:58-66). For the default accounts that is 0 (outer) or 1 (inner) because of `setNodes({0,1})`. A custom account without `setNodes` would key on its last (hardened) node.

#### Default accounts by seed type
- **ArmoryLegacy / ArmoryLegacyPublic:** one `AccountType_ArmoryLegacy`, main (W/Wallets.cpp:1190-1210, 1377-1390).
- **BIP32_Structured and BIP39:** three BIP32 accounts (W/Wallets.cpp:1247-1343):
  - `m/44'/coin'/0'` + {0,1}: types {P2PKH, P2PKH|Uncompressed}, default P2PKH, **main** (:1250-1275)
  - `m/49'/coin'/0'` + {0,1}: {P2SH|P2WPKH}, default P2SH-P2WPKH (:1277-1301)
  - `m/84'/coin'/0'` + {0,1}: {P2WPKH}, default P2WPKH (:1303-1325)
  - coin' = `0x80000000` on mainnet (Utils/BitcoinSettings.cpp:43), `0x80000001` on testnet (:47-58) and regtest (:62-73).
- **BIP32_Virgin / BIP32_base58Root:** no accounts (W/Wallets.cpp:1340-1342).
- **No BIP86 / P2TR / taproot.** A case-insensitive grep for `taproot|p2tr|bip86|0x80000056|schnorr` over cppForSwig, armoryengine, qtdialogs and ui returned nothing.
- **Custom BIP32 accounts** with any path can be added through `makeNewBip32AccTypeObject(derPath)` and `createBIP32Account` (W/Wallets.cpp:2195-2204, 1101-1120). The account's `name()` reports BIP44/49/84 only for the exact 3-node `purpose'/coin'/0'` shape (AccountTypes.cpp:379-409).
- **Imports account** (`setupImportAccount`, W/Wallets.cpp:2207-2218): holds individual imported private keys, public keys, script hashes and raw scripts (:2220-2350; AssetAccounts.cpp:934-1110).
- **What the shipping GUI creates:** Python `createWallet` never sets `walletType` (armoryengine/CppBridge.py:735-747). The capnp enum default is `legacy @0` (cppForSwig/capnp/Bridge.capnp:684-692), which maps to `SeedType::ArmoryLegacy` (BridgeAPI/ProtoCommandParser.cpp:1212-1217). Inference: GUI-created "0.97" wallets are **Armory-legacy-chain wallets with LegacyType Armory200** (BridgeAPI/Wallets/Manager.cpp:416-419). BIP39 wallets only come from a restore (`Manager::createNewWallet` has no BIP39 case, :414-464).

#### Outer and inner (receive and change)
- BIP32: `setNodes({0,1})` forks two branches from `.../0'`. `setOuterAccountID(0)` and `setInnerAccountID(1)` (W/Wallets.cpp:1256-1262; AccountTypes.cpp:242-248). Each branch becomes an AssetAccount whose root is the BIP32 node at `m/purpose'/coin'/0'/{0|1}`, stored as an xprv (or xpub for a watching-only wallet) in an `AssetEntry_BIP32Root` with its full derivation path (AddressAccounts.cpp:50-109; resolution AccountTypes.cpp:877-976). Asset index k is derived as the non-hardened child k of that node (W/DerivationScheme.cpp:424-427, 470-472: `nextAsset(i+1)` with start = root index -1). The result is standard `m/purpose'/coin'/0'/{0,1}/k`.
- Legacy: **outer == inner**. The inner ID is empty and defaults to the outer one (AccountTypes.cpp:132-135; AddressAccounts.cpp:348-353). Change addresses come from the same single chain. `isAssetChange` for legacy accounts is a stub that compares a comment against `"[[ Change received ]]"` using a placeholder key `standin_replace_later` (AddressAccounts.cpp:25, 680-698). In effect, change is not tracked.
- New addresses: `getNewAddress` bumps `lastUsedIndex_` on the outer account, and `getNewChangeAddress` does the same on the inner one (AddressAccounts.cpp:607-656; AssetAccounts.cpp:612-662).

#### Lookahead / address pool
- At creation: `params.lookup` keys per asset account (W/Wallets.cpp:1106-1118). For the legacy account it is `lookup-1`, because asset 0 is bootstrapped from the root (:1206-1209; AddressAccounts.cpp:165-189).
- The GUI pool is 10 and the CLI `--keypool` default is 100 (armoryengine/PyBtcWallet.py:105-107; armoryengine/ArmoryUtils.py:112).
- When a requested index has not been computed yet, the chain grows by `DERIVATION_LOOKUP = 100` (W/DerivationScheme.h:25; AssetAccounts.cpp:638-653, 832-835).
- On disk the computed keys are the asset entries. `lastComputedIndex` = highest stored asset index (AssetAccounts.cpp:333-345).

#### Hardening
Hardened levels appear only in the account path (`44'/49'/84'`, `coin'`, `0'`), and they are derived privately in `resolveNodeRoots` (AccountTypes.cpp:961-969). Per-asset derivation is **soft only**: index > 0x7FFFFFFF throws (W/DerivationScheme.cpp:364-367, 438-441, 528-532, 566-570).

---

### 4. Derivation schemes

On-disk format: `varint len | u32 version(1) | u8 scheme | ...` (W/DerivationScheme.cpp:49-165).

#### `DERIVATIONSCHEME_LEGACY 0xA0` (DerivationScheme.h:19), payload: varint cc
- Private step: `priv[i+1] = priv[i] * (chaincode XOR hash256(pub65(priv[i]))) mod n` (W/DerivationScheme.cpp:227-256 → Utils/Cryptography.cpp:345-381). `computePublicKey` defaults to **uncompressed** (Utils/Cryptography.h:174), so the hash input is the 65-byte pubkey. The XOR runs over 8 uint32 words, which is equivalent to a bytewise XOR.
- Public step: `pub[i+1] = pub[i] * (chaincode XOR hash256(pub65))`, always fed the uncompressed key (W/DerivationScheme.cpp:185-224, 205; Utils/Cryptography.cpp:444-489).
- Chain origin: the root key (index -1). Asset 0 = one step from the root (AddressAccounts.cpp:165-189).
- Deterministic chaincode (1.35c and Armory200): `getBotchedArmoryHMAC256(key = hash256(root), msg = "Derive Chaincode from Root Key")` (Utils/BtcUtils.cpp:1023-1041). The "botched" HMAC uses a **32-byte** block: the key is zero-padded to 32 bytes (or sha256'd if longer), `sha256((K^0x5c)[32] || sha256((K^0x36)[32] || msg))` (Utils/BtcUtils.cpp:256-284).
- **This is exactly the Armory 1.35 chain.** The 1.35 migration only succeeds when the derived first-address ID equals the old ID (Loader.cpp:546-548), and the per-address scrAddrs of the old file are looked up in the new account (:557-569).

#### `DERIVATIONSCHEME_BIP32 0xA1`, payload: varint cc, u32 depth, u32 leafId
Standard BIP32 CKDpriv/CKDpub from the per-chain root asset (W/DerivationScheme.cpp:354-480, using `BIP32_Node`). Evidence that it is standard:
- The test fixture seed `000102..0f` (gtest/WalletTests.cpp:711) produces BIP32 test-vector-1's `xprv9s21ZrQH143K3QTDL4LX...` (gtest/WalletTests.cpp:736-760).
- libbtc's `btc_hdnode_from_seed` (W/BIP32_Node.cpp:115-122) is not in the shallow clone, so its source is unverified, but the test vector covers it.

#### `DERIVATIONSCHEME_BIP32_SALTED 0xA2`, payload: cc, depth, leafId, varint salt (32 bytes)
- Private key = `CKDpriv(accountRoot, k) * salt mod n`.
- Public key = `CKDpub(accountRootPub, k) * salt` (EC scalar multiply).

Sources: W/DerivationScheme.cpp:519-582; Utils/Cryptography.cpp:383-393; salt length must be 32 (AddressAccounts.cpp:232-234). The salt is a per-account 32-byte value supplied by the caller (`AccountType_BIP32_Salted(tree, salt)`, AccountTypes.cpp:416-428), and it is stored in plaintext in the scheme record. **Keys are not standard BIP32**: every leaf key is multiplied by the salt. In this tree no production code path creates salted accounts; only gtests and `importPublicData` do (W/Wallets.cpp:1924-1948).

#### `DERIVATIONSCHEME_BIP32_ECDH 0xA3`, payload: 8-byte random id
- Single root key pair. Asset k key = `rootPriv * salt_k` (pub = `rootPub * salt_k`).
- Salts are 32 bytes each, stored at `0x85|schemeId|u32 index (BE)` → varint+salt (W/DerivationScheme.cpp:605-916; ECDH_SALT_PREFIX W/Assets.h:24).
- Not BIP32 at all: stealth-like, one salt per address. Created only in gtests and `importPublicData` (W/Wallets.cpp:1979-1984).

---

### 5. Address types

`AddressEntryType` (W/AddressEntryType.h:14-33):
- Base types (low 28 bits, `ADDRESS_TYPE_MASK 0x0FFFFFFF`): `Default=0, P2PKH=1, P2PK=2, P2WPKH=3, Multisig=4, ScriptHash=5, RawScript=6`
- Flags: `Uncompressed=0x10000000` (`ADDRESS_COMPRESSED_MASK`), nesting `P2SH=0x40000000`, `P2WSH=0x80000000` (`ADDRESS_NESTED_MASK 0xC0000000`)

How the flags behave:
- **The compressed flag is inverted:** bit clear = compressed (W/Addresses.cpp:800).
- P2WPKH always uses the compressed key (W/Addresses.cpp:278-298).
- P2PK uses compressed or uncompressed according to the flag (:214-227).
- The nesting wrapper is applied last (W/Addresses.cpp:849-869).
- **There is no P2TR, P2WSH-multisig descriptor, or taproot type.**

Default and allowed types per account:
- Legacy: {P2PKH|Uncompressed (default), P2SH|P2PK (compressed), P2SH|P2WPKH} (AccountTypes.cpp:87-105)
- BIP44: {P2PKH (default), P2PKH|Uncompressed}
- BIP49: {P2SH|P2WPKH}
- BIP84: {P2WPKH} (W/Wallets.cpp:1267-1323)

How the type of each issued address is recorded:
- The account stores its type set and default type (AddressAccounts.cpp:374-381).
- Assets issued with a **non-default** type get an override record `0xD8|AssetId → u32 type` (AddressAccounts.cpp:637-642, 1053-1111). Default-type addresses are **not** recorded.
- On read, an asset's type = override if present, else the account default (AddressAccounts.cpp:1151-1169).
- "Issued" means asset index ≤ `lastUsedIndex_` (AssetAccounts.cpp:354-357).

---

### 6. Metadata worth migrating

- **Wallet label and description:** `WALLET_LABEL_KEY 0x31`, `WALLET_DESCR_KEY 0x32`, varint+string (W/Wallets.cpp:1024-1051, 294-312).
- **Comments:** MetaDataAccount type Comments, id `0x000000C0` (MetaAccounts.h:18; MetaAccounts.cpp:23-43). Records live at `0x90|accountId(4)|u32 index BE` (W/Assets.cpp:1788-1799). Value = `varint len | u32 ver(1) | varint keyLen | key | varint strLen | string`. An empty string deletes the record (:1801-1846). The key is free-form bytes (`BinaryData::fromString(key)`, BridgeAPI/Wallets/Container.cpp:386-390). The Python docstring says the key is a 20-byte addr160 for address comments or a 32-byte tx hash for tx comments (armoryengine/PyBtcWallet.py:248-255). Comments migrated from 1.35 use exactly those keys (Loader.cpp:403-419). Whether the 0.97 GUI uses prefixed 21-byte scrAddrs anywhere is unverified.
- **Address usage:** per asset account `lastUsedIndex_` (0xE4, int32; 0xE3 varint in older files) (AssetAccounts.cpp:237-273, 594-610). It is a high-water mark of issued addresses, not on-chain usage. **No per-address "used" flag or tx history is stored in the wallet.**
- **Per-address type overrides:** 0xD8 records (section 5).
- **Main account:** `MAIN_ACCOUNT_KEY` (W/Wallets.cpp:127-138).
- **AuthPeers meta account** (0xC1, prefixes 0x91-0x94; W/Assets.h:27-30): BIP150 peer keys. Not wallet funds data, so do not migrate.
- `legacyChangeComment` (AddressAccounts.cpp:25) is the only change marker, and it is unused in practice (see section 3).

---

### 7. Legacy 1.35 import

Implemented in `Armory135Header` (BridgeAPI/Wallets/Loader.{h,cpp}). It is triggered by `WalletManager` when a file in the datadir is not an LMDB wallet (BridgeAPI/Wallets/Manager.cpp:548-610, 637-651).

1. **Parse** (Loader.cpp:299-446):
   - Magic `"\xbaWALLET\x00"`, version, network magic, flags (encrypted, watching-only), 6-byte ID → base58, timestamp, 32-byte label, 256-byte description, highestUsedIndex, ROMix KDF params (mem, iter, salt).
   - The root PyBtcAddress, then entries: KEYDATA (20-byte addr160 → address), ADDRCOMMENT (20 bytes), TXCOMMENT (32 bytes), DELETED. OPEVAL throws.
   - Address records: scrAddr, flags, chaincode, chainIndex, depth, IV, privkey, pub65, with checksums (:615-662).
2. **Decrypt the root** (if encrypted): ROMix KDF, then AES-CFB with the per-address IV, checked against pub65 (:471-516). An empty passphrase continues as a watching-only migration.
3. **Seed:** `ClearTextSeed_Armory(root, chaincode, Armory135)`. If `computeChainCode_ArmoryLegacy(root) == stored chaincode` the chaincode is cleared, meaning 1.35c is deterministic (:527-540). Watching-only: `ClearTextSeed_ArmoryPublic(pub65, cc, Armory135)` (:521-525).
4. `createFromSeed` with `lookup = addrMap_.size()` (:462-469, 542-543). **Wallet ID equality is asserted** (:546-548).
5. Address types: each old address with `0 ≤ chainIndex ≤ highestUsedIndex` is matched by unprefixed hash160 against all allowed types. Non-default types are replayed through `getNewAddress(type)`. Then addresses are issued up to `highestUsedIndex` (:556-589).
6. Label, description and comments are copied (:591-606).
7. **Imported keys are dropped:** `//TODO: deal with imports` (:554), and `chainIndex < 0` is skipped (:558).

Uncompressed chains:
- **Yes, the new format holds them natively.** The legacy chain derives through uncompressed pubkeys (section 4), and the legacy account's default type is uncompressed P2PKH (AccountTypes.cpp:90-104).
- `Asset_PublicKey` stores both the 65-byte and 33-byte forms (W/Assets.cpp:895-929, 944-959).
- The legacy root's watching-only copy requires the uncompressed key (W/Assets.cpp:873-882).
- BIP44 accounts also allow uncompressed P2PKH (W/Wallets.cpp:1268-1269).

Python `armoryengine/PyBtcWallet.py` in this tree is a bridge proxy (`PyBtcWallet(proto=...)`, armoryengine/WalletUtils.py:117). It is no longer a file parser.

---

### 8. Recommended importer mapping

`coin'` = 0' on mainnet, 1' on testnet. `[fp/…]` = origin; fp = root fingerprint. Read actual paths from each `AssetEntry_BIP32Root.derivationPath_` (v2) rather than assuming them.

| Source (seed / account / scheme / type) | Standard equivalent | Notes |
|---|---|---|
| **BIP39 seed** (SeedType 8), BIP44 acct, P2PKH | `pkh([fp/44h/coinh/0h]xprv/0/*)`, `/1/*` | Mnemonic = `mnemonic_from_data(entropy)`, **empty passphrase**. Exportable as a real BIP39 phrase. |
| BIP39, BIP49 acct, P2SH-P2WPKH | `sh(wpkh([fp/49h/coinh/0h]xprv/0/*))`, `/1/*` | |
| BIP39, BIP84 acct, P2WPKH | `wpkh([fp/84h/coinh/0h]xprv/0/*)`, `/1/*` | |
| BIP39 → BIP86 | none in source | Adding `tr([fp/86h/coinh/0h]xprv/0/*)` creates a **new** account from the same seed, not a migration |
| **BIP32_Structured** (raw 32-byte BIP32 seed) | same three descriptors, built from `xprv = BIP32(seed)` | **No mnemonic exists.** Import as xprv / raw-seed. Do not present a "BIP39 wallet" for it. |
| BIP32_Virgin / BIP32_base58Root / custom-path BIP32 accounts | `pkh/sh(wpkh)/wpkh(xprv/<path>/{0,1}/*)` according to the account's default type and its 0xD8 overrides | base58Root: use the stored xprv, never `rawEntropy_` |
| BIP44 account, **P2PKH\|Uncompressed** addresses (0xD8 override) | **none** | Descriptors only allow compressed keys from xpubs. Export per key: `pkh(<65-byte hex pub>)` / WIF uncompressed |
| **ArmoryLegacy** account (all LegacyTypes: 1.35a, 1.35c, Armory200) | **none** | Non-BIP32 multiplicative chain. Export the enumerated keys up to max(lastUsedIndex, lastComputed) plus a gap: uncompressed P2PKH → `pkh(<pub65>)` / uncompressed WIF; P2SH-P2PK → `sh(pk(<pub33>))`; P2SH-P2WPKH → `sh(wpkh(<pub33>))`. Keep the root + chaincode (or the 1.35 Easy16 paper data) for future regeneration. |
| BIP32_Salted account | **none** | Leaf = CKD(k) × salt. Export per key. |
| ECDH account | **none** | Root × per-index salt. Export per key, with salts from 0x85 records. |
| Imports account | per key: `pkh/wpkh/sh(wpkh)(<key>)`, `addr()`/`raw()` for script-hash and raw-script imports | |

Notes for implementers:
- Use the asset's recorded type (0xD8) and fall back to the account default. Scan at least to `lastUsedIndex_` on both outer and inner.
- For legacy accounts, outer == inner. Every address belongs to one chain, and change cannot be distinguished.
- A Bitcoin Core `combo(<key>)` covers pkh, wpkh and sh(wpkh) for a compressed key, and only pkh/pk for an uncompressed one.

---

### Open questions / unverified
1. libbtc and trezor-crypto sources (`btc_hdnode_from_seed`, `mnemonic_from_data`, `mnemonic_to_seed`, `mnemonic_to_bits`) are not in the clone. Standardness rests on the BIP32 TV1 gtest only. BIP39 has no in-tree vector that I found.
2. (Resolved) `ArmoryLegacyPublic` seed deserialization throws "implement me!" (Seeds.cpp:325). This is never hit on load, because `createFromPublicSeed` uses `initWalletDbWithPubRoot`, which writes only ROOTASSET_KEY and no WALLET_SEED_KEY (W/Wallets.cpp:1351-1392, 1620-1645). Watching-only legacy wallets therefore carry no seed record; read the root asset instead.
3. (Resolved, minor) The ArmoryLegacyRoot deserializer passes only `pubKeyCompressed` to the ctor (W/Assets.cpp:347-351, 369-373). `Asset_PublicKey(SecureBinaryData&)` always fills both forms from a 33- or 65-byte key (W/Assets.cpp:895-918), and `serialize` writes both (:944-959). Every root this code wrote therefore has a compressed key. Only a hand-crafted file would trip this.
4. Comment key format in native 0.97 wallets (addr160 vs prefixed scrAddr vs address string): unverified beyond the Python docstring.
5. Whether any released or BlockSettle-era files contain BIP32_Salted or ECDH accounts: unknown. Only gtests and public-data import create them here.
6. Easy16 Armory135a/c byte order versus classic 1.35 paper backups (any endianness swap): not compared against the classic python code (not in this tree).
7. The multisig on-disk format is effectively unimplemented. Any existing file of that type cannot be interpreted from this code.
