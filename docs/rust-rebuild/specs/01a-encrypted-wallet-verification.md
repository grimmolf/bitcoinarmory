# Spec 01a — Independent verification of encrypted / locked / pending / watching-only wallet records

Status: verification report for spec 01 (`01-wallet-format-and-crypto.md`). Spec 01's
encrypted-record layout was originally derived from code only, because all three TIAB fixtures in
`fixtures/legacy/` are unencrypted. This report covers two things:

* **Real encrypted wallets written by Armory** with known passphrases (found in the successor
  project). Both decrypt fully with the spec 01 algorithm. One of them holds three genuine
  *pending* (`createPrivKeyNextUnlock`) records.
* **A second derivation from the Python source**, done without starting from spec 01 and then
  diffed against it. The result is 2 substantive discrepancies and 4 omissions or clarifications
  (§6).

Citation keys follow spec 01 (`PBA` = `armoryengine/PyBtcAddress.py`, `PBW` =
`armoryengine/PyBtcWallet.py`). Files in the successor repo are cited with the prefix `goatpig:`.

---

## 1. Method

1. Shallow-cloned `https://github.com/goatpig/BitcoinArmory` (default branch, commit
   `d0294d5913c8c272fbc89ac14c7623dec5ea1404`, 2026-05-20) read-only into the session scratchpad.
   Searched for `*.wallet`, archives and tests that reference legacy wallets. Remote branches are
   `0.97_rc2 cxfreeze_windows dev gh-pages master rc2_fixes`. None of them was fetched, because the
   default branch already provided what was needed.
2. Built a small CLI (`kdf`, `enc`, `dec`, `pub`, `chainpriv`, `chainpub`) around Armory 0.93's
   **original** `cppForSwig/EncryptionUtils.cpp` and the bundled Crypto++. The build uses the same
   flags and sources as `tools/legacy-oracle/build.sh` and lives outside the repo. Before use it
   reproduced spec 01's §14.2 vectors (`bc1f2cd9…3b6d` and `500c4160…23a5`). Every KDF output,
   AES-CFB decryption, public key and chained key quoted below was computed by this C++ oracle.
   The Python port (`kdf_romix`, AES via `cryptography`, `chained_priv`) was run alongside it and
   agreed in every case.
3. Read `PBA` (`serialize` 871, `unserialize` 988, `createFromEncryptedKeyData` 345,
   `enableKeyEncryption` 328, `lock` 520, `unlock` 565, `changeEncryptionKey` 641,
   `extendAddressChain` 765) and `PBW` (`serializeKdfParams` 1423, `unserializeKdfParams` 1452,
   `changeKdfParams` 1570, `changeWalletEncryption` 1618, `packWalletFlags` 1874, `unpackHeader`
   1961, `readWalletFile` 2066, `unlock` 2764, `lock` 2841, `forkOnlineWallet` 1332,
   `writeFreshWalletFile` 1152). Wrote down the layout in §5, then compared it with spec 01 section
   by section (§6).
4. Used goatpig's independent C++ legacy reader (`goatpig:cppForSwig/BridgeAPI/Wallets/Loader.cpp`,
   `Armory135Header::parseFile` and `Armory135Address::parseFromRef`) as a third opinion (§7).

---

## 2. Sources found

| File (in goatpig repo) | sha256 | Passphrase | Evidence for passphrase |
|---|---|---|---|
| `extras/test/FakeWallet123.wallet` (27907 B) | `d87d545de9f680ec57d145e295e83b692e442955cb8c4ca1f3c5a5b276a12b29` | `FakeWallet123` | `goatpig:extras/test/FindPassTest.py:72,83` ("Name of wallet is the password"), `goatpig:extras/test/FOUND_PASSWORD.txt` |
| `extras/test/FakeWallet123_backup.wallet` | identical to the above | same | — |
| `cppForSwig/gtest/input_files/legacy.wallet` (28681 B) | `54fa4582b83632647e0a6272c3751a0fcbbaff3d6833751d19867bc2699bff87` | `testnet` | `goatpig:cppForSwig/gtest/BridgeTests.cpp:3499` (`Migrate_Legacy` test; expects ID `28m472Xbm`, label `legacy1`, descr `migration test`) |
| `pytest/tiab.zip` → `tiab/armory/*.wallet` | byte-identical to `fixtures/legacy/*.wallet` | (unencrypted) | — |

Wallet facts. Both wallets are **mainnet** (magic `f9beb4d9`, `uniqueIDBin[5] = 00`); the TIAB
fixtures are testnet, so both networks are now covered. Both have header version 13500000 and
header flags `0x01`.

| | FakeWallet123 | legacy.wallet |
|---|---|---|
| ID (`uniqueIDBin`) | `2Md4hKbcT` (`9de263d95d00`) | `28m472Xbm` (`840e15d41900`) |
| createDate | 1377529759 (2013-08-26) | 1745394264 (2025-04-23) |
| label / descr | `Fake Wallet 1` / `This is a fake wallet not to be used…` | `legacy1` / `migration test` |
| highestUsed | −1 | 2 |
| KDF mem / iter / salt | 2097152 / 3 / `4302cb86…7f5f6e` | 33554432 / 1 / `ce1fbed0…203fdb` |
| key records | 100 (idx 0..99), all flags `0x07`, depth −1 | 100 (idx 0..99) flags `0x07` depth −1, **plus 3 pending** (idx 100..102) flags `0x0f` depth 1,2,3 |
| comments / imported / deleted entries | none | none |

**Coverage.** These files are now real evidence for *encrypted* records and *pending* records,
plus the header and KDF block in the encrypted state. **Watching-only, imported (−2) and deleted
(0x04) records are still code-derived only.** No `.wallet` in the goatpig tree has header bit 1
set, `chainIndex = −2`, or entry type 0x04.

---

## 3. Decryption results (all primitives from the original C++)

### 3.1 KDF block and key derivation

| Wallet | KDF block bytes 0..48 (u64 mem ‖ u32 iter ‖ salt32 ‖ chk4) | checksum | bytes 48..256 | crypto block (590..846) |
|---|---|---|---|---|
| FakeWallet123 | `0000200000000000 03000000 4302cb8651210c911755fe2fcf62584a4c6a1784ec03e73aa00199acf27f5f6e e8888615` | ok | all zero | all zero |
| legacy.wallet | `0000000200000000 01000000 ce1fbed07b478a72c48a80c8dde6a5f8689b3952e1a2a67e6a56657b58203fdb 4d14df83` | ok | all zero | all zero |

| Wallet | kdfKey = KdfRomix(mem, iter, salt).DeriveKey(passphrase) | C++ = Python port |
|---|---|---|
| FakeWallet123 (`FakeWallet123`) | `f31b9c5713e51702d27085ce85632c2f350866117b81bc10299860a03f28f764` | yes |
| legacy.wallet (`testnet`) | `ff2962603444f55299d6885fc050256a84f60dad2f9f665f282a502b1a36b1fe` | yes (at 32 MiB, the maximum calibrated size) |

These vectors are much stronger than the 1024-byte ones in spec 01's §14.2. They exercise the
non-power-of-small sizes and `iter > 1` against keys that Armory itself produced.

### 3.2 Root key (passphrase verification, spec 01 §6.3)

| Wallet | root IV | root encPriv | decrypted root priv | `pub(priv)` = stored pub65 | hash160 = addr160 |
|---|---|---|---|---|---|
| FakeWallet123 | `f6bf05ca6070bc90fddd1f0ac4de6fd4` | `ea193fdd8c401f32b2677bd4c9b215991679b78b395ac6b06dfa8ae78346387e` | `0d7039960bf05f742eafd4c1edb5f66b8a9cf752167772725842a704d1b5ef77` | ✔ | ✔ |
| legacy.wallet | `efc68d68e76c60dbc16d6536fd9abb28` | `a575507366dbe0cf18fc38c05a488ace3676381e90ce133b0d7580884d7fcb73` | `00c92e44ef9155e17d3067f020eb6f938ab416d882e598b45b7442a8979407ff` | ✔ | ✔ |

* A wrong passphrase (`wrong`) produces a private key whose public key does not match in both
  wallets, so the verification-by-pubkey rule works.
* **Chaincode.** For legacy.wallet, `ArmoryHMAC(hash256(rootPriv), "Derive Chaincode from Root Key")`
  equals the stored chaincode `06030297…6bf7`, which confirms the 32-byte-block HMAC on a real
  encrypted wallet. For **FakeWallet123 (2013) it does not match**: the stored chaincode
  `509dab71…9e8a` is random. This is a 1.35-version file written before deterministic chaincodes
  (1.35a). It fixture-confirms spec 01 §7.1: always use the stored chaincode and never re-derive it.
  goatpig's migrator makes the same distinction (`goatpig:Loader.cpp:531`).
* Wallet ID: `reverse(ADDRBYTE ‖ hash160(pub idx 0)[:5]) == uniqueIDBin` holds in both wallets.

### 3.3 Chained records

For every non-pending chained record (100 in each wallet), the following all hold:
* `AES-CFB-decrypt(kdfKey, IV, encPriv)` equals `ComputeChainedPrivateKey(prev priv, chaincode, prev pub)`.
* `pub(plain)` equals the stored pub65, and `hash160(pub)` equals both addr160 and the entry key.
* The record chaincode equals the root chaincode.
* `chk(encPriv)` equals the stored checksum, so the checksum covers the ciphertext.

All 100 IVs in each wallet are distinct. Indices 0 and 1 were also checked with the C++
`DecryptCFB` and `ComputeChainedPrivateKey` directly (identical results).

Raw 237-byte records (Rust test vectors):

```
legacy.wallet ROOT (file offset 846)
c741a2e30b67170f4aae469893842fc089a205a2ec9e42cb60fecd00070000000000000006030297257c9b05a71889f1bfdaeae21b48de5042532db47288f21ae8506bf7df16935affffffffffffffffffffffffffffffffefc68d68e76c60dbc16d6536fd9abb28ccc78271a575507366dbe0cf18fc38c05a488ace3676381e90ce133b0d7580884d7fcb7371e6f80d047df08169018a639d3e7a09abe320f4c852fab01bd0d82082ff3f86a785e2c9cf42fd2f2aadb8452d62635a1378e09655632c1b9649cf4646c93dec652db10886aaec177affffffff000000000000000000000000ffffffff00000000

legacy.wallet idx 0 (entry @2107, record @2128)  -> plain 6c4e0f88295247ab8b52095520b3a677f8f7b26ad536606f397a7ebbaafce875
19d4150e8434db001d1c65005c65d3bbd2d7cb853050443c60fecd00070000000000000006030297257c9b05a71889f1bfdaeae21b48de5042532db47288f21ae8506bf7df16935a0000000000000000ffffffffffffffff7a26d5209064e9513bfcb5935c1a458a9e987a1919a76385bf79d06cf99eccf80b8aeda88ca2dafa830dfdf91dec089d09a91f0eaf19442104f013cd1612f8db04c21bba3f8df522b52c455f8aad7d87dff9bdbbe768ef375fee6567fff7f4f3225713c85177826cb80a3e8bb66955ec106b298b574eed054e3f0f8d86739a086800000000739a086800000000ffffffff00000000

legacy.wallet idx 1 -> plain f1dfddf3f777db55c8608e6abf324885b9449faf837a2c1dd6bdf8054d5991f6
9e1af6a1da80086088be38137caa23c9104a831cf965cc6260fecd00070000000000000006030297257c9b05a71889f1bfdaeae21b48de5042532db47288f21ae8506bf7df16935a0100000000000000ffffffffffffffff94eb30f27f3de63e060e649281fbd1d956472a16dd6ecf0fe52fa4bc168da4703f1a6b50ec4ee940ed3c858f776f7615af278f1c40fbdc33042f55070d81d3b4c24e1b8f2a781f85fa58fb2e6d685098363f9d6d353bec744dfa0c35f2726601e30ec05a0278d313c7b4ae89cbe1545c3eb59d8f68da26ce7f2937ab04799a086800000000799a086800000000ffffffff00000000

FakeWallet123 ROOT (file offset 846)
66bd1d36228ca7372ea5c9169b9fa6641cf66c24fe1e58b560fecd000700000000000000509dab710ed42bf61b007b303d3203e6291745b69d64a3d0432600de50a09e8aa2525ed3fffffffffffffffffffffffffffffffff6bf05ca6070bc90fddd1f0ac4de6fd4ccf43f68ea193fdd8c401f32b2677bd4c9b215991679b78b395ac6b06dfa8ae78346387e9bd19eb704eadb463f1fb93de7d8d809e2de1f8566e7a5b9edf6bbba449715701939262433e1a212de49af2fe9bdc260051c538beff7e80a07de91ca82224d0b0365bd7054b7c244daffffffff000000000000000000000000ffffffff00000000

FakeWallet123 idx 0 -> plain c48ed169c7f9e898f3a07e5bf968c05365066b9b55a148219da281f2d2cc0ea2
5dd963e29d207cebffa62532f983d1a0dbaff0b20ff407db60fecd000700000000000000509dab710ed42bf61b007b303d3203e6291745b69d64a3d0432600de50a09e8aa2525ed30000000000000000fffffffffffffffffb5c0032004e45f422dfc2e88543f3d79503b9e539e6f500b5ae27178facf23f7fe826fd2a0166daf9df1b9feb7932e16fa55e9546b63e9e04a06e79788f6594f30fe9edc5e69881b899dbcc8b4019fa56ff2a80852eff0d3571d87ce17daa8d8e4b906e35922b32d6f7ac397f3603ef9ed3ec983ec6bca6470dc975c8ffffffff000000000000000000000000ffffffff00000000
```

Field check against spec 01 §3: flags `07 00…` (bits 0, 1, 2) at relative offset 28.
chainIndex/depth are `ff…ff`/`ff…ff` for the root and `00…`/`ff…ff` for idx 0. Each IV is followed
by `chk(IV)`, and the priv slot holds the **ciphertext** followed by `chk(ciphertext)`. All offsets
match spec 01 §3.

### 3.4 Pending (`createPrivKeyNextUnlock`) records, fixture-verified

legacy.wallet idx 99 (the last materialised record) has IV `b4e69483755feac9d3b212e311e0a59c`,
encPriv `1716e5b85bfe73a1df3811f425332b8a4734982c7ae52727afa74e18e8984c9b` and plain
`f40290bc342cb8de923ba41442a448d0ab294f4b8a53d479ef87bde7d8df9051`.

| idx | entry offset | flags | depth (rel 80) | IV/priv slots | decrypt(slot) then `depth` × ComputeChainedPrivateKey | pub matches | pub = ComputeChainedPublicKey(pub idx−1) |
|---:|---:|---|---:|---|---|---|---|
| 100 | 27907 | `0x0f` | 1 | = idx 99 (IV, encPriv) | `40143b3bf77e9b6bb43a65ed4872ea5d81eecbac8ac8943dff729c59b9c1dcf8` | ✔ | ✔ |
| 101 | 28165 | `0x0f` | 2 | = idx 99 (IV, encPriv) | `f5cae4445ad4c0098da84875b3462ee09184a30e1d86c80a12d4f64d95fbcbe6` | ✔ | ✔ |
| 102 | 28423 | `0x0f` | 3 | = idx 99 (IV, encPriv) | `d505e271fa37bbc7f0530756ad68c8ae7b79967ad523df6e36481bcccd2d5cbd` | ✔ | ✔ |

```
legacy.wallet idx 100 (pending, depth 1)
2e95dab08b51ad908e9353526390547288193a748b75ac6f60fecd000f0000000000000006030297257c9b05a71889f1bfdaeae21b48de5042532db47288f21ae8506bf7df16935a64000000000000000100000000000000b4e69483755feac9d3b212e311e0a59c31cdc6131716e5b85bfe73a1df3811f425332b8a4734982c7ae52727afa74e18e8984c9b21ae79a7044a72f8544dc4aafefda2c20a45211cf35ad199175916f9b10547912ea0ef7ed97eb296409c84060aa050ae7473ef58df1cda8bdc328a4506a98b27d8b58598bf38acaf3fffffffff000000000000000000000000ffffffff00000000
legacy.wallet idx 101 (pending, depth 2)
d01831f8ace5b9f78eda742acf6e42ba2bbc6066ad8d54c460fecd000f0000000000000006030297257c9b05a71889f1bfdaeae21b48de5042532db47288f21ae8506bf7df16935a65000000000000000200000000000000b4e69483755feac9d3b212e311e0a59c31cdc6131716e5b85bfe73a1df3811f425332b8a4734982c7ae52727afa74e18e8984c9b21ae79a70483a1fe7707a94b525a75fa1a03aa8c5cc59557ae7e77feb82d1e25a3923ae62aca6a4052209976f86e4f700859b75c74aa70ed0cffb1833a3ce05ba0a442962b036cd18effffffff000000000000000000000000ffffffff00000000
legacy.wallet idx 102 (pending, depth 3)
4dd74d8dc27fbe36f0dd2826752346ffbf40f3c2c1c018e860fecd000f0000000000000006030297257c9b05a71889f1bfdaeae21b48de5042532db47288f21ae8506bf7df16935a66000000000000000300000000000000b4e69483755feac9d3b212e311e0a59c31cdc6131716e5b85bfe73a1df3811f425332b8a4734982c7ae52727afa74e18e8984c9b21ae79a704408adcaa102dc235c57cc8d3ca30b5c23bc752f95ab68e5713ca814eec71f960c422fc70e92c26c7c77d1ede171c9d8c7eb25155e97a5e2d567996860ac8a5df01e64543ffffffff000000000000000000000000ffffffff00000000
```

This confirms spec 01 §3.1, §3.2 and §6.5 exactly:
* All four flag bits (P, K, E, N) are set.
* The slots hold the nearest materialised ancestor's (IV, encPriv) pair, not the record's own key.
* A pending parent propagates the same pair with `depth + 1`.
* The record's own random IV is **not** serialised.
* `chk` fields are the ancestor's checksums.

**Reader rule.** The stored pair plus the stored depth is enough to recover the key:
`priv = chain^depth(AES-CFB-decrypt(kdfKey, slotIV, slotEnc))`. The "n2 unlock fix"
(`PBW:2811-2829`) is an in-memory re-anchoring to the previous chained record. It always gives the
same key and is **not** a format requirement. A writer that materialises a pending record must
write flags `0x07`, depth `0`, a fresh IV and its own ciphertext (`PBA:595-605`, `PBW:2831-2835`).

---

## 4. Synthetic vectors (SYNTHETIC: computed with the original C++ primitives, not written by Armory)

> These bytes were **not** produced by Armory. They are what `changeKdfParams(1024, 1, salt)`
> followed by `changeWalletEncryption(passphrase='abcde')` would write, according to the code reading
> in §5. The root IV is fixed here; real Armory would randomise it, because GDHFnMQ2's root IV slot
> is empty and `enableKeyEncryption(generateIVIfNecessary=True)` (`PBA:336`, `PBW:1701`) generates
> one. KDF and AES come from the C++ oracle; checksums are `sha256d[:4]`. The real-fixture vectors
> in §3 should be preferred. These are extra inputs for the writer path.

Input: `fixtures/legacy/armory_GDHFnMQ2_.wallet` (sha256
`8ccb0bf1be6296399a4bd6b66e0a8821a36afd4bbdd1f1a220c2244d7bf6e5c1`).

| Input | Value |
|---|---|
| passphrase | `abcde` (`6162636465`) |
| mem / iter | 1024 / 1 |
| salt | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| root IV (fixed) | `a0a1a2a3a4a5a6a7a8a9aaabacadaeaf` |
| idx 0 IV (fixed) | `b0b1b2b3b4b5b6b7b8b9babbbcbdbebf` |

| Output | Value |
|---|---|
| kdfKey (C++ KdfRomix) | `a9821ab2581e64880685916c8691e45e1ca5bf58bb291331853458a527e7332c` |
| header @16 (u64 flags) | `0100000000000000` |
| KDF block @334, bytes 0..48 (then 208 × `00`) | `0004000000000000 01000000 000102…1e1f 32a439ff` |
| root plain priv (from fixture) | `e20b2f828f0bb9cd843e65258efa04cd7112784357578f1295bbd507cc7be8ac` |
| root ciphertext (C++ EncryptCFB) / chk | `78661e6bb18182ddc7361af68de64304d62d503220544a38f9e95dc2d64d90e4` / `5e90ca39` |
| root chk(IV) | `9dcf47fe` |
| idx 0 plain / ciphertext / chk | `b10164963028078f4a829b4bc72d396cbbdbd0ceb15ce24e34ada0b6391544f9` / `a16aa9ac05b0ed9baaab59200bae08dc4d7ea91a61e94d5227e8ef080097ea23` / `1797f4fb`; chk(IV) `0f3f2594` |
| wrong passphrase `abcdf` | kdfKey `6b1b2598…98f559`; root pub check fails ✔ |

Only bytes 28 (flags `03` → `07`) and 88..143 (IV, chk, priv, chk) change. All other bytes are
unchanged, including the version, time and block ranges, and depth.

```
ROOT original  (offset 846)
536364abd1d2084bf229e0d3805e7b3913aaf011f14a58e360fecd000300000000000000e7a347003d10e1be87125da4dde514a009c721fcb4f86844bf5f66cf186eda84a685bfe7ffffffffffffffffffffffffffffffff000000000000000000000000000000005df6e0e2e20b2f828f0bb9cd843e65258efa04cd7112784357578f1295bbd507cc7be8ac4c21feb804ebdbd19e385b10169b259429d973910019822ae621d43cd2ead80ac1a0cb6a55ae8317b35dbec73f5db8017582f5e5c9fc4e300126b7d6a9a6059293b4e3fecb1e0b6776ffffffff000000000000000000000000ffffffff00000000
ROOT synthetic encrypted
536364abd1d2084bf229e0d3805e7b3913aaf011f14a58e360fecd000700000000000000e7a347003d10e1be87125da4dde514a009c721fcb4f86844bf5f66cf186eda84a685bfe7ffffffffffffffffffffffffffffffffa0a1a2a3a4a5a6a7a8a9aaabacadaeaf9dcf47fe78661e6bb18182ddc7361af68de64304d62d503220544a38f9e95dc2d64d90e45e90ca3904ebdbd19e385b10169b259429d973910019822ae621d43cd2ead80ac1a0cb6a55ae8317b35dbec73f5db8017582f5e5c9fc4e300126b7d6a9a6059293b4e3fecb1e0b6776ffffffff000000000000000000000000ffffffff00000000
idx 0 original (entry @2107, record @2128)
9e73248c1e8a9540f0715e201349a730a710ccae52dfe28e60fecd000300000000000000e7a347003d10e1be87125da4dde514a009c721fcb4f86844bf5f66cf186eda84a685bfe70000000000000000ffffffffffffffff000000000000000000000000000000005df6e0e2b10164963028078f4a829b4bc72d396cbbdbd0ceb15ce24e34ada0b6391544f9057563e904063eaf1596a02f4a29147aaf8ea732e8bc7e8dae712143b27f5b79b0342094d43128e863d1294379851bc76844fa6970fb33678fd24ea6824830afe5ef89740821ccf5e890cbff520000000090cbff52000000006600000066000000
idx 0 synthetic encrypted
9e73248c1e8a9540f0715e201349a730a710ccae52dfe28e60fecd000700000000000000e7a347003d10e1be87125da4dde514a009c721fcb4f86844bf5f66cf186eda84a685bfe70000000000000000ffffffffffffffffb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0f3f2594a16aa9ac05b0ed9baaab59200bae08dc4d7ea91a61e94d5227e8ef080097ea231797f4fb04063eaf1596a02f4a29147aaf8ea732e8bc7e8dae712143b27f5b79b0342094d43128e863d1294379851bc76844fa6970fb33678fd24ea6824830afe5ef89740821ccf5e890cbff520000000090cbff52000000006600000066000000
```

The spec 01 §14.3 synthetic vector (KDF(`abcde`, 1024, 1, 00×32) → AES-CFB(IV 77×16, aa×32) =
`5b4d449403396ef20b33ee34553d7726d48878a70dba5f32d9cca49d6f220ff2`, chk `993c2522`) was
**reproduced with the C++ oracle**.

---

## 5. Independent derivation from the Python source

### 5.1 Header fields when encryption is on
* Flags u64 @16: bit 0 = `useEncryption`, bit 1 = `watchingOnly` (`PBW:1874-1881`). The reader
  raises on bit 2 (`PBW:1894-1905`). Encrypted wallets are `0x01`; watching-only forks are `0x02`.
* KDF block @334 (256 bytes): `u64 mem ‖ u32 iter ‖ salt[32] ‖ sha256d(first 44)[:4] ‖ 208×00`
  (`PBW:1423-1448`). Reader: all-zero first 44 bytes → no KDF; otherwise verify and correct
  (`PBW:1452-1484`). Written by `changeKdfParams` as a MODIFY at `offsetKdfParams`
  (`PBW:1600-1604`). The decrypt path never clears it.
* Crypto block @590: always 256 zero bytes, and ignored on read (`PBW:1488-1509`).
* After the root record is parsed, `if useEncryption: root.isLocked = wallet.isLocked = True`
  (`PBW:2026-2028`).

### 5.2 Address record when encryption is on (`PBA:871-985`)
* Flags: bit0 = `hasPrivKey()` (enc ≠ ∅ or plain ≠ ∅ or pending, `PBA:120-130`); bit1 = pub ≠ ∅;
  bit2 = `serializeWithEncryption`; bit3 = `createPrivKeyNextUnlock` (`PBA:921-926`).
* `serializeWithEncryption = useEncryption`, except that it is forced off when encPriv is empty
  and plain is not (`PBA:906-917`).
* Slots @88/@108:
  * bit2 and bit3 set: `IVandKey[0]` and `IVandKey[1]` (the ancestor pair).
  * bit2 set only: `binInitVect16` and `binPrivKey32_Encr`.
  * otherwise: `binInitVect16` and `binPrivKey32_Plain` (`PBA:958-975`).
* depth @80 = `createPrivKeyNextUnlock_ChainDepth`. It starts at −1 (`PBA:112`), is set to 1 or
  parent+1 for pending records (`PBA:855-867`), and becomes 0 after materialisation (`PBA:601`).
* **"Locked" has no on-disk form.** `isLocked` is set by the reader for every record whose bit 2 is
  set (`PBW:2109-2110`) and for the root via the header (`PBW:2026-2028`). The encrypted bytes of
  locked and unlocked records are identical, because `serialize` always writes `binPrivKey32_Encr`.
* `unserialize` (`PBA:1060-1075`): IV and priv are kept **only if bit0 is set**. With bit2 and
  bit3 set they go to `IVandKey`; with bit2 only they go to `IV`/`Encr`; otherwise to `IV`/`Plain`.
  With bit0 clear they are dropped. The pubkey is stored even if bit1 is clear (`PBA:1091`).
* `createFromEncryptedKeyData` (`PBA:345-366`): an in-memory constructor (`isLocked = True`,
  `useEncryption = True`). It has no format implications. It is used for imports and recovery.

### 5.3 Lock / unlock / re-key
* `PBA.lock`: if not encrypted or no priv, nothing happens. If encPriv exists and `keyChanged` is
  false, the plaintext is wiped. Otherwise the plaintext is encrypted with the given key, and the IV
  is generated only if `generateIVIfNecessary` is set (else `KeyDataError` 'No Initialization
  Vector available', `PBA:536-539`). With no key it raises `WalletLockError` (`PBA:520-562`).
* `PBA.unlock` (`PBA:565-638`): returns early if not encrypted or not locked (`PBA:572`). For a
  pending record: decrypt the pair, chain `depth` times, clear pending, set depth 0, then
  `lock(generateIVIfNecessary=True)` and `unlock`. Otherwise: decrypt (IV and enc must be 16 and
  32 bytes), then check the pubkey.
* `PBA.changeEncryptionKey` (`PBA:641-680`): `new = None` clears the IV and encPriv and sets
  `useEncryption = False`. Otherwise it re-encrypts with the **existing** IV.
* `PBW.changeWalletEncryption` (`PBW:1618-1724`): every record (including ROOT) goes through
  `enableKeyEncryption(generateIVIfNecessary=True)` and `changeEncryptionKey(old, new)`. The records
  plus the header-flags MODIFY are written in one `walletFileSafeUpdate`.
* `PBW.unlock` (`PBW:2764-2836`): verifies on the root, iterates records in chainIndex order,
  applies the n2 fix, and rewrites the pending records after resolution.

### 5.4 Watching-only fork (`PBW:1332-1375`)
New header: `useEncryption = False`, `watchingOnly = True` (flags `0x02`). `kdf` stays `None`
(`PBW:213`), so the KDF block is all zero. Each record is `copy()`'d, then encPriv and plain are
wiped, `useEncryption = False` and `createPrivKeyNextUnlock = False`, so the flags become `0x02`.
**The IV is not wiped** (see D1). The file is written by `writeFreshWalletFile` (`PBW:1152-1171`).

---

## 6. Discrepancies vs spec 01

| # | Spec 01 § | Spec says | Code / fixture says | Evidence | Impact |
|---|---|---|---|---|---|
| **D1** (substantive) | §9.1, §6.6 (and §0 table) | WO fork: "encPriv/plainPriv/IV wiped … priv/IV slots empty"; §6.6 "every record has … empty IV/priv slots" | The fork assigns to a **non-existent attribute** `binInitVector16`, a typo for `binInitVect16`, so the IV survives. `serialize` with `useEncryption = False` writes `binInitVect16` into the IV slot (`PBA:971-973`). A freshly forked WO file therefore has records with flags `0x02`, **a non-empty IV + chk at rel 88**, and an empty priv slot. This happens for every originally-encrypted record, and for unencrypted chained records that carry random IVs (spec §3.2 note). When Armory next reads the file, `unserialize` drops the IV because bit0 is clear (`PBA:1060`), the re-serialised bytes differ, and the record is rewritten in place with an empty IV (`PBW:2103-2108`; root at `PBW:2018-2024`). On-disk WO files can be in either state. `PyBtcWalletRecovery.createNewWO` also leaves the root IV in place (`armoryengine/PyBtcWalletRecovery.py:1630-1634`). | `PBW:1363` `onlineWallet.addrMap[addr160].binInitVector16 = SecureBinaryData()` | Reader: accept any IV-slot content when bit0 = 0, and do not "fix" it. Writer: emit an empty IV for byte-compatibility with a *normalised* file. The §3.2 table row ("whatever `binInitVect16` holds") is already correct. Fix §6.6 and §9.1. |
| **D2** (substantive, writer only) | §6.4 last bullet | "`changeKdfParams` on an encrypted wallet re-encrypts with the new KDF in the same atomic update (`PBW:1605-1613`)" | `changeWalletEncryption` sets `kdfObj` but **never uses it**. It derives `newKdfKey = self.kdf.DeriveKey(pw)` with the **old** KDF. `verifyEncryptionKey(newKdfKey)` is therefore true, and the "same passphrase" early `return` fires, so **nothing is written**: neither the records nor the new KDF block in `extraFileUpdates`. `changeKdfParams` then sets `self.kdf = newkdf` **in memory only**, and in-memory and on-disk KDF diverge until the next reload. The GUI only calls `changeKdfParams` on unencrypted wallets (`qtdialogs.py:2018-2020`, `PBW:1220`), so no file in the wild is affected. | `PBW:1643-1644`, `PBW:1669`, `PBW:1671-1673`, `PBW:1615` | No reader impact. A Rust writer that wants "change KDF on an encrypted wallet" must implement it properly and not copy this. Correct the spec text. |
| D3 (omission) | §6.4 | — | `changeWalletEncryption` returns early **without writing anything**, including `extraFileUpdates`, when the wallet is already encrypted with the new key ("Attempting to change encryption to same passphrase!"). It raises `WalletLockError` if the wallet is encrypted and locked. | `PBW:1652-1656`, `PBW:1671-1673` | Writer behaviour only. |
| D4 (clarification) | §6.2 | "Changing the passphrase **keeps existing IVs**" | Enabling encryption on an unencrypted wallet *also* keeps any IV already present. `enableKeyEncryption(generateIVIfNecessary=True)` generates a random IV only when the size is < 16. Random IVs that `extendAddressChain` gave unencrypted chained records therefore become the real encryption IVs. Decrypting clears them (`PBA:663-667`), so wallets that were encrypted and then decrypted lose them, as in the TIAB fixtures. | `PBA:336`, `PBW:1701`, `PBA:791-792` | No format change. It explains which IVs are seen. |
| D5 (clarification) | §2.4 / §4 / §6.3 | Locked state is mentioned only as reader side effects | State explicitly that **"locked" is not persisted**: there is no flag or byte for it. A record is locked after load iff bit 2 is set; the wallet is locked iff header bit 0 is set. Locked and unlocked encrypted records serialise identically. | `PBW:2026-2028`, `PBW:2109-2110`, `PBA:961-969` | Documentation. |
| D6 (omission) | §6.3 (`lock`) | Lists `WalletLockError` when no key is given | `PBA.lock` also raises `KeyDataError('No Initialization Vector available')` when encrypting with no IV and `generateIVIfNecessary = False`. | `PBA:536-539` | Writer error path only. |
| — | §0 table, §16 | Encrypted and pending entries are "Code-derived only — no fixture contains them" | Now **fixture-verified** with two Armory-written encrypted wallets (§2, §3), including three pending records. Watching-only, imported and deleted records remain code-derived. | this report | Update the status table. |

**Confirmed without change.** The following sections match both the source re-read and the
fixtures: §2 offsets (identical in the encrypted files), §2.1 bits 0 and 1, §2.3 KDF block layout,
checksum and padding (both fixtures), and §2.3 "decide by flag bit 0, not KDF presence" (goatpig
agrees, `Loader.cpp:364`). Also matching: §3 record offsets and checksum-over-ciphertext; §3.1 flag
bits (`0x07`, `0x0f` observed); the §3.2 table rows *Encrypted* and *Pending*; and the §3.3
unserialize algorithm. The rest of §3.2–§7.3 also matches:
* §5 KdfRomix (2 MiB/3 iter and 32 MiB/1 iter vectors).
* §6.1 AES-256-CFB with no padding.
* §6.3 root-only verification via pubkey.
* §6.5 pending construction, resolution, depth semantics and the "own IV not serialised" rule.
* §7.1 stored-chaincode rule, with a real non-deterministic-chaincode file (FakeWallet123).
* §7.2/§7.3 chain derivation on encrypted keys.

---

## 7. goatpig's independent C++ reader (`goatpig:cppForSwig/BridgeAPI/Wallets/Loader.cpp`)

This reader agrees with spec 01 on:
* the header offsets and the header flag masks `0x1`/`0x2` (`:331-332`);
* the KDF block layout (`u64` mem, `u32` iter, 32-byte salt, 4-byte checksum; `:359-372`);
* the 237-byte record layout and the address-flag masks `0x1`/`0x2`/`0x4` (`:631-633`);
* entry types 0/1/2/3/4;
* passphrase verification by decrypting the root and comparing the pubkey (`:470-505`).

Its divergences are **its own implementation choices**, not spec errors. A Rust port should follow
spec 01 instead:
* It ignores bit 3 and depth. This is safe for migration, which only decrypts the root.
* Its checksum check accepts *zero value + zero checksum* but **rejects** Armory's real
  empty-field encoding (zeros + `5df6e0e2`), so an empty pubkey or chaincode would fail (`:285-296`).
* It skips the IV checksum when bit 2 is clear and the priv checksum when bit 0 is clear
  (`:647`, `:654`).
* It verifies the KDF checksum only when header bit 0 is set (`:364`).
* It treats an unknown entry type as fatal (`:434`), whereas Python skips 1 byte.
* It reads labels with `strnlen` (`:346`), whereas Python strips NULs at both ends.
* It detects a deterministic chaincode via `computeChainCode_ArmoryLegacy(root) == stored`
  (`:531`).

---

## 8. Recommended edits to spec 01

1. §0 table: move "Encrypted address entries" and "pending entries" to *Fixture-verified*, citing
   this report (goatpig `legacy.wallet` and `FakeWallet123.wallet`). Keep watching-only, imported,
   deleted and PKCC as code-derived.
2. §6.6 and §9.1: replace "IV wiped / empty IV slots" with D1, which documents the `PBW:1363` typo
   and the normalisation on the next read.
3. §6.4: fix the `changeKdfParams`-on-encrypted bullet (D2) and add the same-passphrase early
   return (D3).
4. §6.2: note D4. §2.4/§4: add D5 ("locked is not persisted").
5. §14: add the §3 vectors (kdfKeys, root and idx 0/1 records, pending idx 100–102) as
   fixture-derived test vectors. Reference the goatpig files by sha256. They do not need to be
   vendored unless the Rust tests require them; if they are, record their provenance (goatpig repo,
   MIT, commit `d0294d59`).
6. §16: the open uncertainty about "no encrypted or pending bytes" is resolved.

## 9. Reproduction notes
* KDF/AES/EC oracle: a CLI wrapper around `cppForSwig/EncryptionUtils.cpp`, built with the same
  command line as `tools/legacy-oracle/build.sh`. Subcommands: `kdf <pwhex> <mem> <iter> <salt>`,
  `enc|dec <key> <iv> <data>`, `pub <priv>`, `chainpriv <priv> <cc> [pub]`, `chainpub <pub> <cc>`.
  It is a candidate for extending `tools/legacy-oracle/harness.cpp`.
* Wall time: KDF 2 MiB × 3 takes 0.05 s in C++ and 0.26 s in the Python port; 32 MiB × 1 takes
  0.27 s and 1.3 s.
