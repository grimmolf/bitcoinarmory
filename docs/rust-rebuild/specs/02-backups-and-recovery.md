# Spec 02 — Backups and Recovery (paper, SecurePrint, fragments, watch-only root, recovery tool)

Status: derived from source at commit `2a6fc53` by reading code only (Python 2 is not
installed). Algorithms marked **[verified]** were re-implemented in a python3 port and
checked against every hardcoded vector in the repo's tests (section 9). Values marked
**[port-generated]** come from that port and have **not** been checked against the original
Python 2 / C++ build — treat them as regression vectors for the Rust port, not as ground truth.

Port location (throwaway): `/tmp/claude-0/-home-user-bitcoinarmory/a3b55be7-b74a-5b21-a2aa-6cd278fc969e/scratchpad/backups/`
(`armory_backup.py`, `run_tests.py`, `vectors.py`, `vectors.out`, `errrate.py`).

Notation: `||` is concatenation. "BE"/"LE" mean big-/little-endian. All Python line refs
are `file:line` at the commit above. `qtdialogs.py` is at repo root.

---------------------------------------------------------------------------------------

## 0. Shared primitives (must be bit-exact)

### 0.1 Hashes
- `sha256`, `sha512`: standard (`ArmoryUtils.py:1806-1811`).
- `hash256(x) = sha256(sha256(x))` (`ArmoryUtils.py:1815-1817`). C++ `SecureBinaryData::getHash256()`
  is the same double-SHA256 (`EncryptionUtils.h:186`, `BinaryData.h:961`).
- `hash160(x) = ripemd160(sha256(x))` (`ArmoryUtils.py:1818-1820`).

### 0.2 Armory HMAC — NON-STANDARD (critical)
`ArmoryUtils.py:1823-1833`:
```python
def HMAC(key, msg, hashfunc=sha512, hashsz=None):
   hashsz = len(hashfunc('')) if hashsz==None else hashsz
   key = (hashfunc(key) if len(key)>hashsz else key)
   key = key.ljust(hashsz, '\x00')
   okey = ''.join([chr(ord('\x5c')^ord(c)) for c in key])
   ikey = ''.join([chr(ord('\x36')^ord(c)) for c in key])
   return hashfunc( okey + hashfunc(ikey + msg) )
HMAC256 = lambda key,msg: HMAC(key, msg, sha256, 32)
HMAC512 = lambda key,msg: HMAC(key, msg, sha512, 64)
```
The key is padded/hashed to the **digest size** (32 for SHA-256, 64 for SHA-512), *not* the
hash block size (64 / 128) that RFC 2104 uses. Therefore `HMAC256 != HMAC-SHA256` and
`HMAC512 != HMAC-SHA512` for every key. **Do not use the `hmac` crate.** Implement:
```
armory_hmac(H, hs, key, msg):
  if len(key) > hs: key = H(key)
  key = key zero-padded on the right to hs bytes
  return H((key ^ 0x5c..) || H((key ^ 0x36..) || msg))
```
Verified in the port that both differ from RFC HMAC for a sample key (`run_tests.py`, "hmac … != rfc").
Users in this spec: `DeriveChaincodeFromRootKey` (HMAC256), SplitSecret coefficient chain
(HMAC512), SecurePrint code (HMAC512), recovery "LogMult" multipliers (HMAC256).

### 0.3 Integer/byte conversions (Python 2 semantics)
- `binary_to_int(b, endIn=LITTLEENDIAN)` — **default is little-endian** (`ArmoryUtils.py:1965-1970`).
- `int_to_binary(i, widthBytes=0, endOut=LITTLEENDIAN)` (`ArmoryUtils.py:1956-1963`, via `int_to_hex`
  at `1897-1915`): minimal even-length hex (0 → `00`, i.e. one byte), left-zero-padded to
  `widthBytes` if shorter; **never truncates**; then byte-reversed unless `BIGENDIAN`.
- `int_to_hex(i)` = hex of `int_to_binary(i)` (lowercase). For a 1-byte value it is just `'%02x'`.
- `hex_to_binary`/`binary_to_hex`: lowercase hex, no endianness switch unless asked (`1922-1951`).

### 0.4 Base58 (`ArmoryUtils.py:1997-2051`)
Alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` (`ArmoryUtils.py:137`).
Encode: big-endian bignum → base58 digits, prefixed by one `'1'` per leading `0x00` byte. No checksum.
Decode: leading `'1'`s → that many `0x00`; any char outside alphabet raises `NonBase58CharacterError`.

### 0.5 Checksum helper
`computeChecksum(b, nBytes=4, hashFunc=hash256) = hash256(b)[:nBytes]` (`ArmoryUtils.py:2319-2320`).

### 0.6 Chaincode derivation from root key
`ArmoryUtils.py:3423-3425`:
```python
def DeriveChaincodeFromRootKey(sbdPrivKey):
   return SecureBinaryData( HMAC256( sbdPrivKey.getHash256(), 'Derive Chaincode from Root Key'))
```
i.e. `chain = armory_hmac(sha256, 32, key=hash256(priv32), msg=b"Derive Chaincode from Root Key")`
(30-byte ASCII message). `createNewWallet` uses this whenever no chaincode is supplied
(`armoryengine/PyBtcWallet.py:833-839`), so all wallets created by ≥1.35a code have a derivable chaincode.

### 0.7 Wallet ID (needed to validate restores)
`newWltID = binary_to_base58((ADDRBYTE + first.getAddr160()[:5])[::-1])` (`qtdialogs.py:12508`,
`13297`; `armoryengine/PyBtcAddress.py:24-29` `calcWalletIDFromRoot`). `first` is chain index 0
derived from the root: `ComputeChainedPrivateKey` (`cppForSwig/EncryptionUtils.cpp:747-776`):
`mult = hash256(rootPub65) XOR chaincode` (as 32 bytes), `newPriv = (BE(mult) * BE(priv)) mod n`;
`getAddr160 = hash160(uncompressed 65-byte pubkey)`. `uniqueIDBin` is the 6-byte reversed value
(last byte = network byte, `0x00` on mainnet). Full chaining semantics belong to the wallet spec;
this spec only needs `wallet_id(priv, chain)`.

---------------------------------------------------------------------------------------

## 1. Easy16 encoding and single-sheet paper backups

### 1.0 Entry points (UI flow)
- New-wallet wizard page 4 "Backup Wallet" (`ui/Wizards.py:251-257`, warning if skipped `138-150`)
  and the wallet "Backup" dialog both use `WalletBackupFrame.clickedDoIt` (`ui/WalletFrames.py:952-992`):
  Single paper / Fragmented paper → `OpenPaperBackupWindow('Single'|'Frag', …)`; digital
  (decrypted/encrypted wallet copy) → `makeWalletCopy`; individual key list → `DlgShowKeyList`.
- `OpenPaperBackupWindow` (`qtdialogs.py:7494-7549`): unlock if encrypted, run `DlgPrintBackup` or
  `DlgFragBackup`, then offer "Verify Your Backup!" → `DlgRestoreSingle` / `DlgRestoreFragged` in
  **test mode** with `expectWltID = wlt.uniqueIDB58` (nothing written to disk).
- Restore entry: `DlgUniversalRestoreSelect` (`qtdialogs.py:12143-12240`): radio Single-Sheet /
  Fragmented / digital-or-WO wallet file / watching-only root data, plus a "test recovery" checkbox.
- Watch-only root data export: `makeWalletCopy(..., 'PKCC', 'rootpubkey')` and
  `DlgWODataPrintBackup` (§5). Recovery tool: menu "Fix Damaged Wallet" (`ArmoryQt.py:745`, `3541-3542`).

### 1.1 Alphabet (`ArmoryUtils.py:2161-2175`)
```
hex   : 0 1 2 3 4 5 6 7 8 9 a b c d e f
easy16: a s d f g h j k w e r t u i o n
```
- `binary_to_easyType16(b)`: lowercase hex of `b`, each hex digit mapped by the table (2 chars/byte,
  high nibble first).
- `easyType16_to_binary(s)`: each char mapped back; **any char not in the table (including uppercase,
  digits, tabs) becomes hex `0`** ("to facilitate possibly later recovery … from the checksum",
  `2172-2175`). Odd character count → Python raises (hex decode error); callers treat that as a line error.

[verified] `binary_to_easyType16(0123456789abcdef) = "asdfghjkwertuion"`.

### 1.2 One backup line = 16 data bytes + 2 checksum bytes (`ArmoryUtils.py:2178-2187`)
```python
def makeSixteenBytesEasy(b16):
   if not len(b16)==16: raise ValueError('Must supply 16-byte input')
   chk2 = computeChecksum(b16, nBytes=2)          # hash256(b16)[:2]
   et18 = binary_to_easyType16(b16 + chk2)        # 36 chars
   nineQuads = [et18[i*4:(i+1)*4] for i in range(9)]
   first4  = ' '.join(nineQuads[:4])
   second4 = ' '.join(nineQuads[4:8])
   last1   = nineQuads[8]
   return '  '.join([first4, second4, last1])
```
Exact layout (46 chars): `QQQQ QQQQ QQQQ QQQQ␣␣QQQQ QQQQ QQQQ QQQQ␣␣CCCC` — single spaces inside the
two 4-quad groups, **two spaces** between groups; the 9th quad `CCCC` is exactly the 2-byte checksum.
Dialogs tell users "9 columns of 4 characters each" (`qtdialogs.py:7530`, `6997`, `7006`).
Variant: `DlgShowKeyList` prints the same 36 chars with single spaces between all 9 quads
(`qtdialogs.py:5458-5473`). Parsers strip all `' '` so both forms are equivalent.

[verified] `makeSixteenBytesEasy(00*16) = "aaaa aaaa aaaa aaaa  aaaa aaaa aaaa aaaa  wsnu"`,
`makeSixteenBytesEasy(aa*16) = "rrrr rrrr rrrr rrrr  rrrr rrrr rrrr rrrr  sksi"` (computed from
plain SHA-256, so high confidence).

### 1.3 Reading a line (`ArmoryUtils.py:2189-2204`)
```python
def readSixteenEasyBytes(et18):
   b18 = easyType16_to_binary(et18.strip().replace(' ',''))
   if len(b18)!=18: raise ValueError('Must supply 18-byte input')
   b16 = b18[:16]; chk = b18[16:]
   if chk=='': return (b16, 'No_Checksum')        # unreachable: length already forced to 18
   b16new = verifyChecksum(b16, chk)              # section 2
   if len(b16new)==0:   return ('','Error_2+')
   elif not b16new==b16: return (b16new,'Fixed_1')
   else:                return (b16new,None)
```
Return codes: `None` = accepted as-is (this **includes** "data fine, a checksum byte is wrong"
— see 2.2 step 5); `'Fixed_1'` = data changed (single-byte fix **or** reversed-endian match);
`'Error_2+'` = uncorrectable. `'No_Checksum'` cannot occur.

### 1.4 What the single sheet contains (`DlgPrintBackup`, `qtdialogs.py:6824-7495`)
Inputs: `binPriv = ROOT.binPrivKey32_Plain` (32 B), `binChain = ROOT.chaincode` (32 B)
(`6842-6843`). Rule for omitting the chaincode (`6874-6879`):
```python
testChain = DeriveChaincodeFromRootKey(self.binPriv)
self.noNeedChaincode = (testChain == self.binChain)
```
Printed data lines (`7411-7425`):

| Prefix printed | Data | Present when |
|---|---|---|
| `Root Key:` | `makeSixteenBytesEasy(K[:16])` | always |
| *(blank)* | `makeSixteenBytesEasy(K[16:])` | always |
| `Chaincode:` | `makeSixteenBytesEasy(C[:16])` | only if `not noNeedChaincode` |
| *(blank)* | `makeSixteenBytesEasy(C[16:])` | only if `not noNeedChaincode` |

where `K, C = binPriv, binChain` (unencrypted) or `binPrivCrypt, binChainCrypt` (SecurePrint, §3) (`7413-7418`).
Header column (`7240-7245`): `Wallet Version:` = `'1.35' + ('c' if noNeedChaincode else 'a')`,
`Wallet ID:` (base58 wallet ID), `Wallet Name:`, `Backup Type:` = `Single-Sheet  (Unencrypted)` or
`Single-Sheet  (SecurePrint™)` (`7230-7238`). So **1.35c = 2 data lines, 1.35a = 4 data lines**.
QR code (convenience only) encodes `'\n'.join(Lines)` — the formatted easy16 lines with spaces, no
prefixes, no SecurePrint code (`qtdialogs.py:7455`).

Imported keys (optional extra pages, `SingleSheetImported`, `7360-7378`): for each imported address
(`chainIndex == -2`), 32-byte key (SecurePrint-masked if enabled — same key/IV as root, §3.5),
`encodePrivKeyBase58(key || ('\x01' if compressed))` = base58(`PRIVKEYBYTE || key [|| 01] || hash256(...)[:4]`)
(`ArmoryUtils.py:2880-2883`), printed in groups of 6 chars plus `(1Addr…)` hint (first 12 chars).
These are **not** covered by the root-key backup.

Other producers of the same 2-line format: `extras/PromoKit.py:105-113` (root key only),
`extras/frag_wallet.py:126-129` (always prints all 4 lines to console).

### 1.5 How restore distinguishes 1.35a vs 1.35c — it does not
`DlgRestoreSingle` (`qtdialogs.py:12280-12600`) makes the **user choose** a radio button
(`12305-12318`): `Version 1.35 (4 lines)`, `Version 1.35a (4 lines Unencrypted)`,
`Version 1.35a (4 lines + SecurePrint™)`, `Version 1.35c (2 lines Unencrypted)` (**default**),
`Version 1.35c (2 lines + SecurePrint™)`. `changeType` (`12400-12420`) sets
`visList = [SP, L1, L2, L3, L4]`: 1.35 and 1.35a → `[0,1,1,1,1]`; 1.35a+SP → `[1,1,1,1,1]`;
1.35c → `[0,1,1,0,0]`; 1.35c+SP → `[1,1,1,0,0]`; `isLongForm = visList[-1]==1`.
"Version 1.35" is behaviourally identical to 1.35a unencrypted. The only printed hints are the
`Wallet Version: 1.35a/1.35c` string and the line count; the only *check* is that the user confirms
the recomputed wallet ID (`12526-12533`) or, in test mode, `verifyRecoveryTestID` (`13785+`).
(Fragments, by contrast, carry machine-readable type via line count — §4.8.)

Restore algorithm (`verifyUserInput`, `12425-12508`):
1. Input mask `'<AAAA\ AAAA\ AAAA\ AAAA\ \ AAAA\ AAAA\ AAAA\ AAAA\ \ AAAA!'` (`12338`): 36 letters,
   forced lowercase.
2. For each of `nLine = 4 if isLongForm else 2` lines: `readSixteenEasyBytes(text.replace(' ',''))`;
   `Error_2+` or any exception → error dialog naming the line, abort; `Fixed_1` → count it.
3. If any fixed: warn "Detected N error(s)… verify the Wallet Unique ID" (`12465-12476`).
4. `privKey = L1||L2`; if long form `chain = L3||L4` (`12480-12482`).
5. If SecurePrint: validate code (§3.3 `checkSecurePrintCode`), `maskKey = KDF(code)`,
   `privKey = unmask(privKey)`, and `chain = unmask(chain)` if long form (`12484-12497`).
6. If short form: `chain = DeriveChaincodeFromRootKey(privKey)` (`12499-12500`).
7. Compute wallet ID (§0.7); test mode → `verifyRecoveryTestID` and stop; otherwise confirm ID,
   optional new passphrase, `createNewWallet(plainRootKey, chaincode, …)`, fill 1000 addresses
   (`12502-12600`). Label `'Restored - ' + ID`.

Legacy, unreferenced: `DlgImportPaperWallet` (`qtdialogs.py:4145-4303`) — always 4 lines, no
SecurePrint, treats `Fixed_1`/`No_Checksum` as "corrected"; no code path instantiates it.

---------------------------------------------------------------------------------------

## 2. Checksum verification and single-error correction

### 2.1 `fixChecksumError` (`ArmoryUtils.py:2303-2317`)
```python
for byte in range(len(binaryStr)):               # position ascending
   binaryArray = list(binaryStr)                 # fresh copy per position
   for val in range(256):                        # value ascending, includes original value
      binaryArray[byte] = chr(val)
      if hashFunc(''.join(binaryArray)).startswith(chksum): return ''.join(binaryArray)
return ''
```
First hit in (position asc, value asc) order wins. Cost ≤ 16×256 = 4096 double-SHA256 per line.

### 2.2 `verifyChecksum(b, chk, hashFunc=hash256, fixIfNecessary=True, beQuiet=False)` (`2323-2377`)
Exact control flow (Rust must mirror the `elif` fall-through):
```
bin1 = b; bin2 = reverse(b)
1. if H(bin1) startswith chk:            return bin1
2. elif H(bin2) startswith chk:          if fixIfNecessary: return bin2     (else fall to 5)
3. elif fixIfNecessary:
      f = fixChecksumError(bin1, chk)
      if f != '':                        return f
      elif chk == 5df6e0e2 (hash256('')[:4]): return ''      # cannot fire for 2-byte chk
4. (no step: fall-through from 2 when fixIfNecessary is False, or from 3 when no fix found)
5. # "ID a checksum byte error":
   h = H(bin1)
   for i in 0..len(chk)-1:
      for v in 0..255:
         c' = chk with byte i := v
         if h startswith c':              return bin1        # data assumed correct
6. return ''
```
For paper lines `chk` is 2 bytes and `H = hash256`. Consequences (empirical, `errrate.py`,
600 random lines each): 1 wrong data char → 581 correct fixes, 19 *wrong* `Fixed_1`;
1 wrong checksum char → 561 `None` (correct data), 39 wrong `Fixed_1` (data search runs before the
checksum-byte search); 2 wrong data chars → 567 `Error_2+`, 26 wrong `Fixed_1`, 7 silently wrong
`None`. This is why every restore ends in "verify the wallet ID". Rust must reproduce the same
order so outcomes are identical.

[verified] testArmoryEngineUtils.py:112-122 vectors (§9.4).

### 2.3 Where it is used in this feature
Every easy16 line (`readSixteenEasyBytes`), the WO root-ID line (`verifyChecksum` on 7 bytes with a
2-byte checksum, §5), and the private-key parser (`parsePrivateKeyData`, 4-byte checksum,
`ArmoryUtils.py:2855-2872`).

---------------------------------------------------------------------------------------

## 3. SecurePrint™

### 3.1 `HardcodedKeyMaskParams` — complete transcription (`ArmoryUtils.py:3442-3503`)
```python
def HardcodedKeyMaskParams():
   paramMap = {}

   # Nothing up my sleeve!  Need some hardcoded random numbers to use for
   # encryption IV and salt.  Using the first 256 digits of Pi for the
   # the IV, and first 256 digits of e for the salt (hashed)
   digits_pi = ( \
      'ARMORY_ENCRYPTION_INITIALIZATION_VECTOR_'
      '1415926535897932384626433832795028841971693993751058209749445923'
      '0781640628620899862803482534211706798214808651328230664709384460'
      '9550582231725359408128481117450284102701938521105559644622948954'
      '9303819644288109756659334461284756482337867831652712019091456485')
   digits_e = ( \
      'ARMORY_KEY_DERIVATION_FUNCTION_SALT_'
      '7182818284590452353602874713526624977572470936999595749669676277'
      '2407663035354759457138217852516642742746639193200305992181741359'
      '6629043572900334295260595630738132328627943490763233829880753195'
      '2510190115738341879307021540891499348841675092447614606680822648')

   paramMap['IV']    = SecureBinaryData( hash256(digits_pi)[:16] )
   paramMap['SALT']  = SecureBinaryData( hash256(digits_e) )
   paramMap['KDFBYTES'] = long(16*MEGABYTE)

   def hardcodeCreateSecurePrintPassphrase(secret):
      if isinstance(secret, basestring):
         secret = SecureBinaryData(secret)
      bin7 = HMAC512(secret.getHash256(), paramMap['SALT'].toBinStr())[:7]
      out,bin7 = SecureBinaryData(binary_to_base58(bin7 + hash256(bin7)[0])), None
      return out

   def hardcodeCheckSecurePrintCode(securePrintCode):
      if isinstance(securePrintCode, basestring):
         pwd = base58_to_binary(securePrintCode)
      else:
         pwd = base58_to_binary(securePrintCode.toBinStr())

      isgood,pwd = (hash256(pwd[:7])[0] == pwd[-1]), None
      return isgood

   def hardcodeApplyKdf(secret):
      if isinstance(secret, basestring):
         secret = SecureBinaryData(secret)
      kdf = KdfRomix()
      kdf.usePrecomputedKdfParams(paramMap['KDFBYTES'], 1, paramMap['SALT'])
      return kdf.DeriveKey(secret)

   def hardcodeMask(secret, passphrase=None, ekey=None):
      if not ekey:
         ekey = hardcodeApplyKdf(passphrase)
      return CryptoAES().EncryptCBC(secret, ekey, paramMap['IV'])

   def hardcodeUnmask(secret, passphrase=None, ekey=None):
      if not ekey:
         ekey = hardcodeApplyKdf(passphrase)
      return CryptoAES().DecryptCBC(secret, ekey, paramMap['IV'])

   paramMap['FUNC_PWD']    = hardcodeCreateSecurePrintPassphrase
   paramMap['FUNC_KDF']    = hardcodeApplyKdf
   paramMap['FUNC_MASK']   = hardcodeMask
   paramMap['FUNC_UNMASK'] = hardcodeUnmask
   paramMap['FUNC_CHKPWD'] = hardcodeCheckSecurePrintCode
   return paramMap
```
The digit strings are concatenated with no separators: `digits_pi` = 40-byte prefix + 256 digits
(296 ASCII bytes), `digits_e` = 36-byte prefix + 256 digits (292 bytes). `MEGABYTE = 1024*1024.0`
(`ArmoryUtils.py:168-169`) → `KDFBYTES = 16777216`.

Constants (pure SHA-256 of the literals, computed by the port — high confidence):
```
IV   = b928d97f9c81ad16baeb12a19845068e
SALT = 68287df541e90879dde18208b45fd80f59de7c969abc2adf580fc449c1b89652
```

### 3.2 SecurePrint code generation
`secret` passed by every caller is **`rootPriv32 || chaincode32` (64 bytes)** — for single-sheet
(`qtdialogs.py:6902`) and fragments (`12117`), even for 1.35c wallets whose chaincode is not printed:
```
bin7  = armory_hmac(sha512, 64, key = hash256(secret64), msg = SALT)[:7]
code  = base58(bin7 || hash256(bin7)[0:1])          # 8 bytes → typically 11 chars (10 or fewer
                                                     # only with small leading values; '1' per 00)
```
The code is case-sensitive, deterministic per wallet (reprinting gives the same code), and the same
for every fragment of a wallet. It is shown on screen only, never printed (user writes it in the red
"Code:" box drawn at 4.0 in from left on the page, `7326-7348`).

### 3.3 Code validation (`checkSecurePrintCode`, `qtdialogs.py:12257-12278`)
1. `len(code.strip()) < 9` → "Invalid Code" (reject).
2. `FUNC_CHKPWD(code)`: `pwd = base58_decode(code)`; good iff `hash256(pwd[:7])[0] == pwd[-1]`
   (uses whatever length decodes; no length check).
3. Non-base58 char → "unrecognized characters" (reject).

### 3.4 KDF: `KdfRomix(16 MiB, 1 iteration, SALT)` (`cppForSwig/EncryptionUtils.cpp:186-292`)
The KDF **password is the ASCII text of the base58 code** (not its decoded bytes):
`FUNC_KDF(self.randpass)` where `randpass` is `SecureBinaryData(base58 string)` (`qtdialogs.py:6903`,
`12118`); restore passes the typed string (`12494`, `13253`, `3077`). Algorithm (`DeriveKey_OneIter`, `212-280`):
```
HSZ = 64 (SHA-512); mem = 16777216; seqCount = mem/HSZ = 262144; nLookups = seqCount/2 = 131072
LUT[0]   = sha512(password || SALT)
LUT[i+1] = sha512(LUT[i])  for i = 0 .. seqCount-2
X = LUT[seqCount-1]
repeat nLookups times:
    j = u32_le(X[60..64]) mod seqCount        # *(uint32_t*)(X+HSZ-4); x86/ARM native LE
    X = sha512(X XOR LUT[j])
key32 = X[0..32]
```
`DeriveKey` applies `numIterations_` (=1) rounds feeding the 32-byte output back as password
(`283-290`). Output = 32 bytes = AES-256 key. Python port takes ~0.7 s.

### 3.5 Mask / unmask = AES-256-CBC, fixed IV, no padding
`CryptoAES::EncryptCBC/DecryptCBC` (`EncryptionUtils.cpp:368-420`) use Crypto++
`CBC_Mode<AES>` with `ProcessData` — no padding, output length = input length, inputs must be a
multiple of 16 (always 32 or 64 here). Key = KDF output (32 B), IV = the fixed 16-byte `IV` of 3.1.
What is masked:
- Single sheet: `binPrivCrypt = AES(priv32)`, `binChainCrypt = AES(chain32)` — two **independent**
  CBC encryptions each starting from IV (`qtdialogs.py:6906-6909`).
- Imported keys: each 32-byte key independently (`6911-6915`).
- Fragments: only the y-value (32 or 64 B, one CBC stream over 64 B for 1.35a); x is never masked
  (`6918-6921`, `12119-12121`). The ID line marks it (`M | 0x80`, §4.6).
- Restore: `FUNC_UNMASK` on the concatenated 32-byte (or 64-byte frag Y) blocks with the same IV.
Because the IV and key are fixed per wallet, masking is deterministic.

Imported-key restore with SecurePrint is in `DlgImportAddress` (`qtdialogs.py:2954-2968`,
`3062-3077`, `3270-3287`): `parsePrivateKeyData` then `FUNC_UNMASK`. Caveat: a compressed imported key
is printed with a trailing `01` (38-byte payload) which `parsePrivateKeyData` returns unparsed
(`ArmoryUtils.py:2855-2874`), so unmasking would get 38 bytes — **appears broken in original**
(not verified at runtime).

---------------------------------------------------------------------------------------

## 4. Fragmented backups (Shamir secret sharing)

### 4.1 Finite field (`ArmoryUtils.py:2449-2564`)
Prime field `GF(p)` selected by byte width:

| nbytes | prime | | nbytes | prime |
|---|---|---|---|---|
| 1 | 2^8 − 5 | | 48 | 2^384 − 317 |
| 2 | 2^16 − 39 | | 64 | 2^512 − 569 |
| 4 | 2^32 − 5 | | 96 | 2^768 − 825 |
| 8 | 2^64 − 59 | | 128 | 2^1024 − 105 |
| 16 | 2^128 − 797 | | 192 | 2^1536 − 3453 |
| 20 | 2^160 − 543 | | 256 | 2^2048 − 1157 |
| 24 | 2^192 − 333 | | | |
| 32 | 2^256 − 357 | | | |

Any other width → `FiniteFieldError`. Only 32 and 64 are used by backups (1/8/16 in tests).
Operations (Python `%` = non-negative remainder; Rust must use `rem_euclid` semantics):
- `add=(a+b)%p`, `subtract=(a-b)%p`, `mult=(a*b)%p`.
- `power(a,b)`: right-to-left square-and-multiply, `result=(result*(a if bit else 1))%p; a=a*a%p`.
- `powinv(a)=power(a,p-2)`; note `powinv(0)=0` (no error). `divide(a,b)=mult(a,powinv(b))`.
- `mtrxrmrowcol(m,r,c)`: requires square (else logs, returns `[]`); drops row r, col c.
- `mtrxdet(m)`: 1×1 → `m[0][0]` **unreduced**; non-square → `-1`; else Laplace expansion on row 0:
  `result = add(result, mult(m[0][i]*(-1 if i odd else 1), det(minor(0,i))))`.
- `mtrxmultvect(m,v)`: `[ sum(mult(m[i][j],v[j]) for j<N) % p for i<M ]`.
- `mtrxmult(m1,m2)`: bug-compatible — column range uses `N1` (cols of m1), not cols of m2
  (`2545-2551`); unused by backups, exercised by tests.
- `mtrxadjoint(m)[i][j] = ((-1)^(i+j) * det(minor(j,i))) % p` (note transposed minor indices).
- `mtrxinv(m)[i][j] = divide(adj[i][j], det)`. A singular matrix (det=0, e.g. duplicate x) is **not
  detected**: result is the all-zero matrix (test vector §9.1 depends on this).

### 4.2 `SplitSecret(secret, needed, pieces, nbytes=None, use_random_x=False)` (`2568-2616`)
```
nbytes = nbytes or len(secret); ff = FiniteField(nbytes)
a = int_BE(secret)
require a < p                 else FiniteFieldError
require pieces >= needed      else FiniteFieldError
require 2 <= needed <= 8      (needed==1 or needed>8 → FiniteFieldError)
lasthmac = secret
othernum = []
for i in 0 .. pieces+needed-2:                          # pieces+needed-1 values
    lasthmac = HMAC512(lasthmac, b"splitsecrets")[:nbytes]   # Armory HMAC; key = previous value
    othernum.append( int_LE(lasthmac) )                      # ** LITTLE-endian **
poly(x) = a*x^(needed-1) + Σ_{i=0}^{needed-2} othernum[i] * x^(needed-2-i)   (all mod p)
for i in 0 .. pieces-1:
    x = othernum[i+2] if use_random_x else i+1
    frag[i] = [ int_to_binary(x, nbytes, BE), int_to_binary(poly(x), nbytes, BE) ]
```
Key facts:
- **The secret is the leading coefficient** (of `x^(needed-1)`), not the constant term.
- Coefficients are deterministic from the secret → same secret + same M ⇒ identical fragments, and
  fragment *i* does not depend on `pieces`. Coefficients are not reduced mod p before use (mult reduces).
- x is 1-based (`i+1`). `use_random_x` is never passed by any caller. With `nbytes` < 64, the
  HMAC key (previous output) is ≤ 64 bytes so it is never pre-hashed (only `nbytes>64` widths would).
- Fragment encoding: both x and y BE, fixed width `nbytes`.

### 4.3 `ReconstructSecret(fragments, needed, nbytes)` (`2620-2636`)
```
pairs = fragments[:needed]                     # extra fragments silently ignored
for (x,y) in pairs: row = [x^(needed-1), x^(needed-2), ..., x^0]  (ff.power), v.append(y)
minv = mtrxinv(Vandermonde)                    # adjoint/determinant method of 4.1
out  = mtrxmultvect(minv, v)
return int_to_binary(out[0], nbytes, BE)       # coefficient of x^(needed-1) = secret
```
x and y are parsed as BE integers of any length. Rust may use Gaussian elimination / Lagrange
interpolation for speed **only if** it reproduces identical results including the degenerate cases
(duplicate x ⇒ det 0 ⇒ output `00…00`). The safest choice is a literal port (M ≤ 8, cofactor
expansion is cheap enough: 8! terms).

**Shift invariance (important for restore):** because the secret is the leading coefficient, replacing
every x by x+c (constant c) still yields the same `out[0]` (the polynomial `f(t−c)` has the same
leading coefficient). The GUI exploits/relies on this accidentally — see 4.8. [verified] in port for
c=0 (exact x), c=+1 (GUI), and 1-byte x (unfrag_wallet).

### 4.4 What secret is split (`DlgFragBackup`, `qtdialogs.py:11719-12140`)
```python
self.secureRoot  = ROOT.binPrivKey32_Plain; self.secureChain = ROOT.chaincode       # 11772-11773
if DeriveChaincodeFromRootKey(self.secureRoot) == self.secureChain:
    self.securePrint = self.secureRoot                     # 32 bytes  → "1.35c" fragments
else:
    self.securePrint = self.secureRoot + self.secureChain  # 64 bytes  → "1.35a" fragments
insecureData = SplitSecret(self.securePrint, M, self.maxmaxN)   # maxmaxN = 12   (11744, 12107)
```
- **Always 12 fragments are computed**, regardless of the chosen N; N only selects how many are
  shown/printed (indices 0..N−1). M ∈ 2..5 (standard) or 2..8 (expert); N ∈ M..6 or M..12
  (`11741-11753`, `11834-11850`).
- SecurePrint versions: `secureMtrxCrypt[i] = [x, AES_CBC(y)]` with code from `root||chain` (`12113-12121`).
- `extras/frag_wallet.py` always splits the 64-byte `priv||chain` (`frag_wallet.py:136-137`), so for
  1.35c wallets its fragments differ from GUI fragments; for 1.35a wallets they are identical for the same M.

### 4.5 Fragment set ID (base58) (`ArmoryUtils.py:2706-2710`)
```
ComputeFragIDBase58(M, wltIDBin6) = str(M) + base58( hash256(wltIDBin6 || u32_BE(M))[:4] )
```
Displayed as `<FragIDBase58>-#<n>` (n = 1-based fragment number) on printouts (`7249-7259`) and in
`ReadFragIDLineBin` (`2731`); `DlgFragBackup` labels show `<prefix>-<n>` without `#` (`11910-11911`).
[port-generated] `ComputeFragIDBase58(3, 00*6) = "34ZFkPT"`.

### 4.6 Fragment ID line (hex, not easy16) (`ArmoryUtils.py:2713-2721`)
```
byte0 = (0x80 + M) if isSecure else M
byte1 = index + 1                       # == the x coordinate used by SplitSecret
bytes2..7 = wltIDBin (6 bytes, uniqueIDBin)
hex = lowercase hex of the 8 bytes (16 chars); addSpaces → 4 groups of 4: "0201 bad4 ab48 0100"
```
Reader (`2725-2737`): `doMask = byte0 > 127`, `M = byte0 & 0x7f`, `fnum = byte1`, `wltID = bytes[2:]`,
`idBase58 = ComputeFragIDBase58(M, wltID) + '-#' + str(fnum)`. No checksum on the ID line.

### 4.7 Printed / saved fragment layout
Printed page (`qtdialogs.py:7381-7404`), saved file (`12015-12045`), and QR (`'\n'.join(Lines)`):

| Prefix | 32-byte Y (1.35c) | 64-byte Y (1.35a) |
|---|---|---|
| `ID:` | `ComputeFragIDLineHex(M, idx, wltIDBin, doMask, addSpaces=True)` | same |
| `F1:` | `makeSixteenBytesEasy(Y[0:16])` | `Y[0:16]` |
| `F2:` | `makeSixteenBytesEasy(Y[16:32])` | `Y[16:32]` |
| `F3:` | — | `Y[32:48]` |
| `F4:` | — | `Y[48:64]` |

Y is masked if SecurePrint. X is never printed (implicit from the ID byte1).
Page header: `Wallet Version: 1.35a|c`, `Wallet ID`, `Wallet Name`, `Backup Type: Fragmented Backup (M-of-N) (SecurePrint™|Unencrypted)`,
`Fragment: <FragIDStr>-#n` (`7246-7258`); text counts "three"/"five" lines (`7287-7290`).

Saved `.frag` file (`clickSaveFrag`, `11984-12045`), default name
`wallet_<wltIDB58>_<FragIDBase58>_num<n>_need<M>.<'secure.' if masked>frag`:
```
Wallet ID:     <wltIDB58>\n
Create Date:   <unixTimeToFormatStr(now)>\n
Fragment ID:   <FragIDBase58>-#<n>\n
Frag Needed:   <M>\n
\n\n
ID: <id line with spaces>\n
F1: <easy16 line>\n
F2: ...\n            (F3:, F4: for 64-byte)
```
(When SecurePrint is on, the user is asked whether to mask the file too; "No" saves unmasked.)

Legacy `extras/frag_wallet.py` file (`frag_wallet.py:139-176`): free-text header, then
`ID: <same hex line>` and lowercase `f1:`..`f4:` lines with the 64-byte Y; filename
`wallet_<wltID>_frag<n>_need_<M>.txt`. Older script versions emitted 9 lines
(`ID`, `x1..x4`, `y1..y4`) — "Version 0" (`qtdialogs.py:41`, `13678`).

### 4.8 Fragment restore and validation (`DlgRestoreFragged`, `DlgEnterOneFrag`)
Input paths:
- **Typed** (`DlgEnterOneFrag`, `13542-13783`): user picks type (Version 0 / 1.35a / 1.35a+SP /
  1.35c / 1.35c+SP, default 1.35c); ID typed as hex with mask `'<HHHH\ HHHH\ HHHH\ HHHH!'` (`13626`).
  If an SP type is selected the code is validated (§3.3); if a non-SP type is selected but the ID's
  first byte > 127 → error "ID field indicates SecurePrint" (`13705-13740`). Lines read with
  `readSixteenEasyBytes`; `fragData = [idBin, line1, line2, ...]`; user confirms `fid`.
- **File** (`dataLoad`, `13051-13102`): each line `.strip()`ed; if `line[:2].lower()` ∈
  {id,x1..x4,y1..y4,f1..f4} then `fragMap[key] = line[3:].strip().replace(' ','')` (last occurrence
  wins). Count of keys: 9 → x/y (Version 0), 5 → f1..f4 (1.35a), 3 → f1..f2 (1.35c), else abort.
  `fragData[0] = hex_to_binary(fragMap['id'])`; `Error_2+` on any line aborts. (Uppercase letters are
  not lowercased here → decoded as nibble 0 → then checksum-corrected or rejected.)

`addFragToTable` (`13158-13226`) validation & coordinates:
1. Type from `len(fragData)`: 9 → `'0'`, 5 → `1.35a`, 3 → `1.35c`; all rows must share one type.
2. If ID says masked and no code entered yet → prompt `DlgEnterSecurePrintCode` (validates per §3.3).
3. Fragment-set prefix (`idBase58.split('-')[0]`, i.e. M + wallet-ID hash) must match all rows.
4. Reject duplicate `fnum`.
5. Coordinates: Version 0 → `X = x1||x2||x3||x4` (64 B), `Y = y1..y4`; 1.35a →
   **`X = int_to_binary(fnum + 1, 64, BE)`**, `Y = F1..F4`; 1.35c → `X = int_to_binary(fnum + 1, 32, BE)`,
   `Y = F1||F2` (`13212-13220`).

   **x-offset discrepancy:** `fnum` already equals the SplitSecret x (`index+1`), so the GUI uses
   x+1. `extras/unfrag_wallet.py:115-117` uses x = `hex_to_binary(id[2:4])` (exact). Both recover
   the correct secret because of 4.3 shift invariance [verified]. A Rust port should use the exact x
   (`fnum`) — results are identical for all fragment sets — but must not "fix" anything else.
6. Restore enabled when `#rows ≥ M` (`13133`).

`processFrags` (`13240-13385`): `maskKey = KDF(code)` if any row masked; for each row,
`Y = unmask(Y)` iff that row's ID has the 0x80 flag (mixed masked/unmasked rows allowed);
`nBytes = {'0':64, 1.35a:64, 1.35c:32}`; if test mode and more than M rows → subset test (below);
else `SECRET = ReconstructSecret(rows, M, nBytes)` (uses the first M rows in dict order).
`len 64` → `priv = S[:32], chain = S[32:]`; `len 32` → `priv = S`, `chain = DeriveChaincodeFromRootKey(priv)`.
Then wallet ID confirm / test check, wallet creation as in 1.5. No integrity check exists beyond
per-line checksums and the human comparing wallet IDs.

Subset testing (`testFragSubsets` `13387-13414`; `createTestingSubsets` `ArmoryUtils.py:2640-2681`;
`testReconstructSecrets` `2685-2702`): `fragMap` keyed by `int_BE(X) − 1` (= fragment number). If
`C(n,M) ≤ maxTestCount` (100 in GUI): enumerate `x in 0..2^n−1`, bitset LSB-first (`int_to_bitset`),
keep popcount==M, map bit i → `fragIndices[i]`, return `(False, sorted(subs))`; else draw
`maxTestCount` distinct random sorted M-subsets → `(True, sorted)`. M==n → `(False,[tuple(all)])`;
M>n → `KeyDataError`. Each subset → wallet ID via `calcWalletIDFromRoot`; `DlgShowTestResults`
shows ✓ when ID equals expected (or the first subset's ID if none expected).

`extras/unfrag_wallet.py` (`1-244`): parses the same prefixes; checks all files share M
(`id[0:2]`, **no 0x7f mask — SecurePrint fragments unsupported**), same wallet ID, network byte,
no duplicate fnum; always `ReconstructSecret(fragMtrx, M, 64)` (**1.35c 32-byte fragments
unsupported**); prints recovered 4 easy16 lines; `--test` or >M files → 20 random-subset trials.

---------------------------------------------------------------------------------------

## 5. Watching-only root data ("PKCC") backup / restore

Producer `PyBtcWallet.getRootPKCCBackupData(pkIsCompressed=True, et16=True)`
(`armoryengine/PyBtcWallet.py:1260-1308`), constants `PYROOTPKCCVER=1`, `VERMASK=0x7F`,
`SIGNMASK=0x80` (`39-41`):
```
pub33  = compress(ROOT.binPublicKey65)                       # 02/03 || X
ver    = 0x01 ^ (0x80 if pub33[0]==0x03 else 0)
idBin  = ver(1) || uniqueIDBin(6) || hash256(ver||uniqueIDBin)[:2]       # 9 bytes
idLine = easy16(idBin) split into 4-char groups joined by ' ' → "xxxx xxxx xxxx xxxx xx" (5 groups)
data   = pub33[1:33] || chaincode32                          # 64 bytes
lines  = [makeSixteenBytesEasy(data[i:i+16]) for i in 0,16,32,48]
```
Printed by `DlgWODataPrintBackup` (`qtdialogs.py:11526-11715`): `Watch-Only Root ID:` + idLine,
`Watch-Only Root:` + 4 lines; QR = `'\n'.join([idLine]+lines)`. No SecurePrint, no fragments.
File `writePKCCFile` (`PyBtcWallet.py:1311-1329`), extension `.rootpubkey`, default name
`armory_<wltIDB58>.rootpubkey` (`ArmoryQt.py:1728-1743`): `"1\n" + idLine + "\n" + 4×(line + "\n")`.

Restore `DlgRestoreWOData` (`qtdialogs.py:12605-12845`):
1. File load: `read().splitlines()`; `int(lines[0]) != 1` → silently ignore; fill ID from line 2,
   data from lines 3-6 (`12699-12719`).
2. ID: mask `'<AAAA\ AAAA\ AAAA\ AAAA\ AA!'`; `rawID = easyType16_to_binary(text without spaces)`;
   must be 9 bytes; `verifyChecksum(rawID[:7], rawID[7:9])` (fixes ≤1 byte; ''→error) (`12733-12748`).
3. Data: 4 lines via `readSixteenEasyBytes` (`12768-12793`).
4. `sign = ((ver & 0x80) >> 7) + 2`; `pub65 = UncompressPoint(sign || L1 || L2)`;
   `chain = L3 || L4`; version bits `ver & 0x7f` read but ignored (`12795-12800`).
5. `newWltID = base58(idBytes[1:7])` — taken **from the ID line, not recomputed from the key data**
   (`12807`). Test mode compares only this; a mismatch between ID line and key/chain lines is not
   detected. `createNewWalletFromPKCC` (`PyBtcWallet.py:684-760`) recomputes the real ID from the
   first chained address; refuses to replace an already-loaded wallet with the same (line) ID.
[port-generated] vectors in §9.6.

---------------------------------------------------------------------------------------

## 6. Wallet recovery tool (`armoryengine/PyBtcWalletRecovery.py`)

### 6.1 Modes (`RECOVERMODE = enum('NotSet','Stripped','Bare','Full','Meta','Check')`, line 32)
`NotSet=0, Stripped=1, Bare=2, Full=3, Meta=4, Check=5` (`enum` = `ArmoryUtils.py:1712-1714`).
- **Stripped**: only re-create a wallet from root key + chaincode (header). For non-WO wallets returns
  right after unlocking (`546-560`); for WO wallets there is no early return (behaves like Bare).
- **Bare**: parse all entries, verify chain integrity; on errors re-create wallet with root, chain
  addresses, imported keys; comments skipped.
- **Full**: Bare + collect address/tx comments and copy them; also builds a recovered WO wallet for
  watch-only inputs (`1140`).
- **Meta**: no recovery; returns dict `{shortLabel, longLabel, naddress, ncomments, 0..n-1:[rawData,
  hashVal, dtype]}` (`563-565`, `676-678`, `717-722`). Used by `DlgReplaceWallet` "Merge" (`qtdialogs.py:13926-13937`).
- **Check**: consistency check only; locked wallet without passphrase treated as watch-only (`486-528`);
  never writes a recovered wallet (`1141` requires mode < Meta). Used at startup via
  `WalletConsistencyCheck` (`1666-1675`, returns `[code, strOutput]`) and by armoryd (`armoryd.py:3335`, `Mode=5`).
UI: `DlgWltRecoverWallet` (`qtdialogs.py:13941-14200`) radio Stripped/Bare/Full(default)/Check; Full on a
loaded wallet → `FixWalletList` (moves files), otherwise `ParseWallet` (`FixWallet(..., DoNotMove=True)`).

### 6.2 ProcessWallet pipeline (`392-1258`)
1. Missing file → −1. `doWalletFileConsistencyCheck()` exception → −2. `unpackHeader` exception → −1;
   negative return (wrong network) → −3.
2. Encrypted & not Meta: passphrase may be `str`, `SecureBinaryData`, or callable(wallet) → SBD;
   missing → −4 (Check: treat as WO). `kdf` missing → −10; `verifyEncryptionKey` fails → −4;
   `rootAddr.unlock` fails → −12.
3. Read all entries with `unpackNextEntry`. On exception: log raw error, `LookForFurtherEntry`
   (`1302-1445`) heuristically resyncs (try address entry at +1+20, skip 1+20+237 bytes, try
   addr-comment, tx-comment, deleted entry, else advance 1 byte recursively). Address entries
   (`dtype 0`) with `chainIndex > -2` go to `addrDict[chainIndex] = [addr, hashVal, seqNo, offset, raw]`;
   `chainIndex ≤ -2` → `importedDict`. Comments kept for Full/Meta/Check. OPEVAL/unknown → `misc`.
4. Root checks: root pubkey derived from root privkey; chain index 0 derived from root (`696-711`).
5. Per chained address (`730-1030`): re-serialize vs raw (`byteError`); pubkey valid EC point
   (`invalidPubKey`) or missing (`missingPubKey`); chaincode equals index-0 chaincode
   (`chainCodeCorruption`); file order (`brokenSequence`, not counted in nErrors); index gaps
   (`sequenceGaps`); recompute pubkey chain from previous present entry (`forkedPublicKeyChain`);
   (non-WO) encryption flag mismatch, missing private key (`misc`), unlock failure / pub≠priv
   (`unmatchedPair`), recompute private key chain (from previous entry or root) — if the stored key
   differs, mark `isPrivForked`, store the bad entry as an import with `chainIndex = -3 - chainIndex`
   and continue with the valid key; `addrStr20 != hashVal` → `hashValMismatch`.
6. Imported entries (`1033-1130`): byte errors, pub validity/missing, missing priv, encryption flag,
   pub/priv match, hashVal (only when `chainIndex == 2`, effectively never) → `importedErr`;
   `chainIndex < -2` → `negativeImports`.
7. `nerrors = rawError+byteError+sequenceGaps+forkedPublicKeyChain+chainCodeCorruption+invalidPubKey
   +missingPubKey+hashValMismatch+unmatchedPair+importedErr+misc` (`1133-1137`).
8. If nerrors and (`not WO` or Full) and mode < Meta (`1139-1240`): `createRecoveredWallet` →
   `<dir>/armory_<ID>_RECOVERED[_WatchOnly].wallet` (existing file deleted first; −2 on failure)
   via `createNewWallet(root, chain, same labels, same passphrase)` or `createNewWO` (`1613-1646`);
   compute `naddress−1` further chain addresses; re-add every import (re-encrypted with the new KDF
   key). For negative imports, log a **privacy-preserving multiplier**:
   `regQ = HMAC256(rootPriv, "LogMult%d" % nonce)` with the first nonce making `BE(regQ) < n`;
   `privMult = badPriv * regQ^{-1} mod n` (hex appended to `privKeyMultipliers`, sanity-checked
   `privMult * regQ == badPriv`) (`1172-1207`, `1649-1663`). Full: re-add comments.
9. Return `BuildLogFile(0 if nerrors==0 else 1)`; Meta returns the dict.

### 6.3 Output log (`BuildLogFile` `103-341`, `FinalizeLog` `344-381`)
Written (append, `'ab'`, CRLF line endings) to `<recovered wallet path>.log` if a recovered wallet
was created, else `<original wallet path>.log`, unless `returnError` is truthy
(`'Dict'` → returns the error dict `{byteError, brokenSequence, sequenceGaps, forkedPublicKeyChain,
chainCodeCorruption, invalidPubKey, missingPubKey, hashValMismatch, unmatchedPair, misc, importedErr,
negativeImports, nErrors, privMult}`; other truthy → `[code, strOutput]`). Lines, in order:
`Analyzing wallet '<label>' (ID: <id>) on <ctime>` (Check: `Checking wallet …`),
`Using recovery mode: <n>` (not in Check), `Wallet is Watch Only` | `Wallet contains private keys
and doesn't use encryption|and uses encryption`, `Highest used index: <n>`; Stripped stops with
`   Recovered root key and chaincode, stripped recovery done.`; otherwise file size/read bytes,
counts, then one block per error list (each either a "no errors" sentence or a count plus
`   chainIndex X at file offset Y` lines), imported-key block, multipliers block
(`Inconsistent private keys were found!` / `Logging Multipliers (no private key data):`),
`<n> errors were found`, then `Recovery done` (or `Recovery failed: error code <n>` for negatives
with messages: −1 invalid path/not a wallet, −2 file I/O, −3 other network, −4 bad/missing
passphrase, −10 no KDF params, −12 failed to unlock root key). Exact strings are at the cited
lines; the Rust port should reproduce them if log compatibility matters.

### 6.4 `FixWallet` file moves (`1685-1785`)
On errors and not `DoNotMove`: folder `<walletDir>/<wltID>/<YYYY-MM-DD-HHMM>/`; original saved as
`armory_<ID>_ORIGINAL__WatchOnly.wallet` (string bug: suffix always `_WatchOnly`, `1724`) — as a WO
fork (`forkOnlineWallet`) then deleted if it had private keys, else renamed; log moved to
`armory_<ID>_LOGFILE_[_WatchOnly].log`; `armory_<ID>_RECOVERED.wallet` renamed onto the original path;
both `_backup` wallets removed; `armorylog.txt`, `armorycpplog.txt`, `multipliers.txt` copied.
Returns `(0,0,fixer)` clean, `(1,folder|0,fixer)` fixed, `(-1,errstr,fixer)` failure.

### 6.5 Source bugs (do not copy blindly; decide per bug)
- `addrEntry_unserialize_recover` (`1448-1610`): uses `self.addrStr20` (AttributeError → caught,
  so "recover damaged entry" always fails), `chksumError and 171`/`and 1` (logical, not bitwise),
  `getSize == 0` (method not called). The damaged-entry path therefore never works as intended.
- `LookForFurtherEntry`: `for i in len(chunk)` (TypeError, caught) in deleted-entry branch;
  unbounded recursion (one frame per byte) on long garbage.
- Stripped + `returnError='Dict'` references `self.misc` before it is set.
- `hashVal` check for imports only when `chainIndex == 2`.

---------------------------------------------------------------------------------------

## 7. Rust implementation checklist (byte-compat)
1. `armory_hmac` (digest-size padding) — never RFC HMAC.
2. `binary_to_int` default LE in SplitSecret coefficient chain; secret, x, y are BE fixed-width.
3. Secret = leading coefficient; x = 1..12; always split 12; M ∈ [2,8].
4. Reconstruction must return `out[0]`, tolerate any x offset, and yield zeros on singular input.
5. Easy16 decode maps unknown chars to nibble 0; reproduce verifyChecksum's exact search order.
6. SecurePrint code from `root||chain` (64 B) always; KDF password = ASCII code string;
   ROMix 16 MiB/1 iter/SALT; AES-256-CBC, fixed IV, no padding; frag Y and each 32-byte key masked separately.
7. Fragment ID line: hex, `M|0x80` secure flag, byte1 = x, 6-byte wallet ID, no checksum.
8. Single-sheet type is user-selected; 1.35c ⇔ chaincode derivable.

---------------------------------------------------------------------------------------

## 8. Port verification summary
`run_tests.py`: **217 checks passed, 0 failed** (python3.11). Covered: every FiniteField assertion
of `testSplitSecret.py:41-60`; all SplitSecret/Reconstruct round trips and raise cases of
`testSplitSecret.py:62-96` and `testFragmentedBackup.py:58-82` (every M-combination); the six
`verifyChecksum` cases of `testArmoryEngineUtils.py:112-122`; easy16 round trip and single-error fix;
HMAC non-standardness; GUI x+1 / exact x / 1-byte x reconstruction equivalence; SecurePrint code
self-check. `vectors.py` additionally checks mask/unmask round trip and 2-of-12 reconstruction.

**Not verified against the original** (no vectors exist in repo): Armory-HMAC outputs
(DeriveChaincode, SplitSecret coefficients, SecurePrint codes), KdfRomix output, AES outputs, wallet
IDs, and the exact fragment y-values. The SplitSecret tests only prove self-consistency
(round-trip), so a Rust port must be validated against vectors produced by the *original* build
before claiming byte compatibility of fragments and SecurePrint codes.

---------------------------------------------------------------------------------------

## 9. Test vectors

### 9.1 `pytest/testSplitSecret.py` (verbatim)
Lines 20-36:
```python
TEST_A = 200
TEST_B = 100
TEST_ADD_RESULT = 49
TEST_SUB_RESULT = 100
TEST_MULT_RESULT = 171
TEST_DIV_RESULT = 2
TEST_MTRX = [[1, 2, 3], [3,4,5], [6,7,8] ]
TEST_VECTER = [1, 2, 3]
TEST_3_BY_2_MTRX = [[1, 2, 3], [3,4,5]]
TEST_2_BY_3_MTRX = [[1, 2], [3,4], [5, 6]]
TEST_RMROW1CO1L_RESULT = [[1, 3], [6, 8]]
TEST_DET_RESULT = 0
TEST_MULT_VECT_RESULT = [14, 26, 44]
TEST_MULT_VECT_RESULT2 = [5, 11, 17]
TEST_MULT_VECT_RESULT3 = [[7, 10], [15, 22], [23, 34]]
TEST_MULT_VECT_RESULT4 = [[248, 5, 249], [6, 241, 4], [248, 5, 249]]
TEST_MULT_VECT_RESULT5 = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
```
Lines 41-72:
```python
   def testFiniteFieldTest(self):
      ff1 = FiniteField(1)
      self.assertRaises(FiniteFieldError, FiniteField, 257)

      self.assertEqual(ff1.add(TEST_A, TEST_B), TEST_ADD_RESULT)
      self.assertEqual(ff1.subtract(TEST_A, TEST_B), TEST_SUB_RESULT)
      self.assertEqual(ff1.mult(TEST_A, TEST_B), TEST_MULT_RESULT)
      self.assertEqual(ff1.divide(TEST_A, TEST_B), TEST_DIV_RESULT)
      self.assertEqual(ff1.mtrxrmrowcol(TEST_MTRX, 1, 1), TEST_RMROW1CO1L_RESULT)
      self.assertEqual(ff1.mtrxrmrowcol(TEST_3_BY_2_MTRX, 1, 1), [])
      self.assertEqual(ff1.mtrxdet([[1]]), 1)
      self.assertEqual(ff1.mtrxdet(TEST_3_BY_2_MTRX), -1)
      self.assertEqual(ff1.mtrxdet(TEST_MTRX), TEST_DET_RESULT)
      self.assertEqual(ff1.mtrxmultvect(TEST_MTRX, TEST_VECTER), TEST_MULT_VECT_RESULT)
      self.assertEqual(ff1.mtrxmultvect(TEST_3_BY_2_MTRX, TEST_VECTER), TEST_MULT_VECT_RESULT[:2])
      self.assertEqual(ff1.mtrxmultvect(TEST_2_BY_3_MTRX, TEST_VECTER), TEST_MULT_VECT_RESULT2)
      self.assertEqual(ff1.mtrxmult(TEST_2_BY_3_MTRX, TEST_3_BY_2_MTRX), TEST_MULT_VECT_RESULT3)
      self.assertEqual(ff1.mtrxmult(TEST_2_BY_3_MTRX, TEST_2_BY_3_MTRX), TEST_MULT_VECT_RESULT3)
      self.assertEqual(ff1.mtrxadjoint(TEST_MTRX), TEST_MULT_VECT_RESULT4)
      self.assertEqual(ff1.mtrxinv(TEST_MTRX), TEST_MULT_VECT_RESULT5)

   def testSplitSecret(self):
      self.callSplitSecret('9f', 2,3)
      self.callSplitSecret('9f', 3,5)
      self.callSplitSecret('9f', 4,7)
      self.callSplitSecret('9f', 5,9)
      self.callSplitSecret('9f', 6,7)
      self.callSplitSecret('9f'*16, 3,5, 16)
      self.callSplitSecret('9f'*16, 7,10, 16)
      self.assertRaises(FiniteFieldError, SplitSecret, '9f'*16, 3, 5, 8)
      self.assertRaises(FiniteFieldError, SplitSecret, '9f', 5,4)
      self.assertRaises(FiniteFieldError, SplitSecret, '9f', 1,1)
```
(`callSplitSecret` at 75-96: `secret = hex_to_binary(secretHex)`, `SplitSecret(secret, M, N)`, 10×
shuffle + `ReconstructSecret(out, M, nbytes)` must equal `secretHex`. Note lines 70-72 pass the raw
ASCII strings `'9f'*16` / `'9f'`, not decoded bytes.)

### 9.2 `pytest/testFragmentedBackup.py` (verbatim)
Lines 17-19:
```python
SECRET = '\x00\x01\x02\x03\x04\x05\x06\x07'

BAD_SECRET = '\xff\xff\xff\xff\xff\xff\xff\xff'
```
Lines 50-82:
```python
   def subtestAllFragmentedBackups(self, secret, m, n):
      fragmentMap = splitSecretToFragmentMap(SplitSecret(secret, m, n))
      for combinationMap in self.getNextCombination(fragmentMap, m):
         fragmentList = [value for value in combinationMap.itervalues()]
         reconSecret = ReconstructSecret(fragmentList, m, len(secret))
         self.assertEqual(reconSecret, secret)
         

   def testFragmentedBackup(self):

      self.subtestAllFragmentedBackups(SECRET, 2, 3)
      self.subtestAllFragmentedBackups(SECRET, 2, 3)
      self.subtestAllFragmentedBackups(SECRET, 3, 4)
      self.subtestAllFragmentedBackups(SECRET, 5, 7)
      self.subtestAllFragmentedBackups(SECRET, 8, 8)
      self.subtestAllFragmentedBackups(SECRET, 2, 12)

      # Secret Too big test
      self.assertRaises(FiniteFieldError, SplitSecret, BAD_SECRET, 2,3)

      # More needed than pieces
      self.assertRaises(FiniteFieldError, SplitSecret, SECRET, 4,3)
      
      # Secret Too many needed needed
      self.assertRaises(FiniteFieldError, SplitSecret, SECRET, 9, 12)

      # Too few pieces needed
      self.assertRaises(FiniteFieldError, SplitSecret, SECRET, 1, 12)
      
      # Test Reconstuction failures
      fragmentList = SplitSecret(SECRET, 3, 5)
      reconSecret = ReconstructSecret(fragmentList[:2], 2, len(SECRET))
      self.assertNotEqual(reconSecret, SECRET)
```

### 9.3 `pytest/testPyBtcWalletRecovery.py` (verbatim, behavioural; needs a full wallet impl)
Line 31: `crpWlt.createNewWallet(walletPath, securePassphrase='testing', doRegisterWithBDM=False)`
Line 39 (corrupt pubkey at the 100th address):
```python
      PubKey = hex_to_binary('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455')
```
Line 49 (unencrypted entry at chainIndex 250 → gap + encryption inconsistency):
```python
      PrivKey = hex_to_binary('e3b0c44298fc1c149afbf4c8996fb92427ae41e5978fe51ca495991b7852b855')
```
Line 61 (bad private key at the last address of 250):
```python
      PrivKey = hex_to_binary('e3b0c44298fc1c149afbf4c8996fb92427ae41e5978fe51ca495991b00000000')
```
Fill sequence: `fillAddressPool(100)` (33), corrupt, `(200)` (43), insert idx 250, `(250)` (58),
corrupt+lock last, `(350)` (70). Assertions, lines 84-95 and 147-152:
```python
      self.assertTrue(len(brkWltResult['sequenceGaps'])==1, \
                      "Sequence Gap Undetected")
      self.assertTrue(len(brkWltResult['forkedPublicKeyChain'])==3, \
                      "Address Chain Forks Undetected")
      self.assertTrue(len(brkWltResult['unmatchedPair'])==100, \
                      "Unmatched Priv/Pub Key Undetected")
      self.assertTrue(len(brkWltResult['misc'])==50, \
                      "Wallet Encryption Inconsistency Undetected")
      self.assertTrue(len(brkWltResult['importedErr'])==50, \
                      "Unexpected Errors Found")         
      self.assertTrue(brkWltResult['nErrors']==204, \
                      "Unexpected Errors Found")   
...
      self.assertTrue(len(rcvWltResult['importedErr'])==50, \
                      "Unexpected Errors Found")         
      self.assertTrue(rcvWltResult['nErrors']==50, \
                      "Unexpected Errors Found")   
      self.assertTrue(len(rcvWltResult['negativeImports'])==99, \
                      "Missing neg Imports")
```
Multiplier check (110-137): `hmacQ = HMAC256(Q, 'LogMult%d' % nonce)` first with `BE < SECP256K1_ORDER`;
`ECMultiplyScalars(privMult[i], hmacQ)` must equal the bad key of `badKeys[i+201]` (sorted by chainIndex).
Recovery is invoked as `RecoverWallet(path, 'testing', RECOVERMODE.Full, returnError='Dict')` (78-80).

### 9.4 `pytest/testArmoryEngineUtils.py` checksum cases (verbatim, lines 112-122)
```python
      data   = hex_to_binary('11' + 'aa'*31)
      dataBE = hex_to_binary('11' + 'aa'*31, endIn=LITTLEENDIAN, endOut=BIGENDIAN)
      dataE1 = hex_to_binary('11' + 'aa'*30 + 'ab')
      dataE2 = hex_to_binary('11' + 'aa'*29 + 'abab')
      dchk = hash256(data)[:4]
      self.callTestFunction('verifyChecksum', data, data, dchk)
      self.callTestFunction('verifyChecksum', data, dataBE, dchk, beQuiet=True)
      self.callTestFunction('verifyChecksum', '',   dataE1, dchk, hash256, False, True)  # don't fix
      self.callTestFunction('verifyChecksum', data, dataE1, dchk, hash256,  True, True)  # try fix
      self.callTestFunction('verifyChecksum', '',   dataE2, dchk, hash256, False, True)  # don't fix
      self.callTestFunction('verifyChecksum', '',   dataE2, dchk, hash256,  True, True)  # try fix
```
(`callTestFunction(name, expected, *args)`.) Lines 86-89 contain a *commented-out*
`binary_to_typingBase16` vector using an older, different alphabet — **not** easy16; ignore it.
There are no hardcoded easy16, SecurePrint, fragment-ID, or PKCC vectors anywhere in the repo
(`pytest/`, `guitest/`, `cppForSwig/gtest/`).

### 9.5 Port-generated vectors — easy16 / SplitSecret [port-generated]
```
easy16(0123456789abcdef)            = asdfghjkwertuion                                   (table only)
makeSixteenBytesEasy(00*16)         = aaaa aaaa aaaa aaaa  aaaa aaaa aaaa aaaa  wsnu
makeSixteenBytesEasy(aa*16)         = rrrr rrrr rrrr rrrr  rrrr rrrr rrrr rrrr  sksi
SplitSecret(0001020304050607, 2, 3) = [0000000000000001, 26b87337afdc8a0b]
                                      [0000000000000002, 26b9753ab3e19012]
                                      [0000000000000003, 26ba773db7e69619]
SplitSecret(9f, 3, 5)  (x,y)        = (01,19) (02,a2) (03,73) (04,87) (05,de)
```

### 9.6 Port-generated end-to-end vectors [port-generated; depend on Armory-HMAC, ROMix, AES, EC]
Full output in `scratchpad/backups/vectors.out`. Mainnet (ADDRBYTE 00).

**Vector A** — root `aa`×32, chaincode derived (→ 1.35c):
```
chaincode       cd0784defd9a0fbc4ecc1b306eb7679b3a9c5a23f340b2453aadc482ed10c5dc
wltIDBin        bad4ab480100     wltIDB58 2c36x2XPM
plain lines     rrrr rrrr rrrr rrrr  rrrr rrrr rrrr rrrr  sksi   (×2)
SecurePrint     8rDHqahJzK8
KDF key         8e358a71ea851cffab60757bb4776d6bcac0fd8af4d54259d65cc0c31a94976c
masked lines    neaj drei hwwo ffih  nkki sdij ajgi nhtf  hhnn
                dkhh hhad fisd gjre  ngts nwwe fgns wjhd  juwg
FragIDBase58(M=2) 2jCLhy
frag #1 plain   ID: 0201 bad4 ab48 0100
                F1: sfth rows jfaf ifsh  kros ejed kfrd hewr  dwtt
                F2: sioi oadn ihai ajig  odhk ijuk gras oiua  wjuf
frag #1 secure  ID: 8201 bad4 ab48 0100
                F1: jrie ehij fswu hnwk  urew husa khng gtnw  tnjk
                F2: oana aksg dukw ofsr  tjeh ttsa dwka oern  fuio
frag #2 plain   ID: 0202 bad4 ab48 0100
                F1: toja hedu airo kiua  dhwu gsfi sogi agfg  taje
                F2: uwew wrir kntk tskn  wiad wsks ngru ewjr  fout
frag #3 plain   ID: 0203 bad4 ab48 0100
                F1: jeat afij twhe dwjr  iafj otok uwnk roin  ghdu
                F2: kfgf fhwh drjd hudr  fkri dusu enhk ggke  wruk
WO root (pub33 026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3)
  ID            astr igrt gwas aaun kh
  data          jrag rtew ieog kkgr  iwaj ofad iiio tjft  tjfe
                orsj thut hndd fook  kgkw owjs tthw fotf  gwwn
                uiak wgio nier antu  gouu stfa jotk jket  dwnh
                freu hrdf nfga tdgh  frri ugwd oisa uhiu  astt
```
**Vector B** — root `0102…20`, chaincode `ff`×32 (not derivable → 1.35a):
```
derived CC      5ff19f177be6935bfbb95c0494d51a5da70776370da977712c298e0f10876a91 (≠ chain)
wltIDBin        956b826de400     wltIDB58 2HQbPnQQf
plain lines     asad afag ahaj akaw  aear atau aiao ansa  grwt
                sssd sfsg shsj sksw  sesr stsu siso snda  gagd
                nnnn nnnn nnnn nnnn  nnnn nnnn nnnn nnnn  aftr   (×2)
SecurePrint     hH3LRdpfVBX
KDF key         19d1e92bdac42747f5a05cf999c93575030b165d457adb1b576279be41a20ef2
masked lines    shha swdj jokh sgwn  jgks irad iosu afds  iweu
                frat ufng ahfr oadt  twrj snku keka todr  neow
                rrid saug odtk eaeh  hgga ufaj ugio nkui  ruiw
                thdj khsd kkai jwrn  rgio ukkn hjsa taaw  koti
FragIDBase58(M=2) 26UeaVb
frag #1 plain   ID: 0201 956b 826d e400
                F1: dkwh owdr efgs wknd  jojd wjia ahan ujnw  ejdd
                F2: giag raak isso dron  idhe isiw hgoo krwi  odnh
                F3: ftag gjwd sjgd jufg  wgwg gjsi jhnj ganr  akro
                F4: dhor dgas dohw diet  wjad wftu jujw kjko  ntnj
frag #1 secure  ID: 8201 956b 826d e400
                F1: kfwt dojf teut dsoi  nhag gdgf gooe srei  wadd
                F2: fsdf affa uwee nifs  osjj fkaf dfdj ergh  jrwd
                F3: wksk srfs kohe jdgh  jdsw kfag knui odoh  orkj
                F4: osfr gfjj tfwa ioot  isrj erkd ikgd ifwj  nkhs
WO root (pub33 0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0)
  ID            aseh jtwd jiog aatr wf
```
(The near-identical F3/F4 lines across vector-B fragments are arithmetic, not a bug: with chain =
`ff…ff` the low 256 bits of `a·x` are `2^256 − x`.)

---------------------------------------------------------------------------------------

## 10. Open uncertainties
1. No original-build vectors for Armory-HMAC, ROMix, AES masking, SecurePrint codes or fragment
   y-values; §9.5/9.6 are self-generated. Highest-value next step: run the original Python 2 build
   once (e.g., in a container with Python 2.7 + the SWIG module) on vectors A/B.
2. KdfRomix index uses native-endian `uint32_t` read; assumed little-endian (all shipped platforms).
3. Crypto++ `CBC_Mode::ProcessData` behaviour on non-multiple-of-16 input (compressed imported keys
   with SecurePrint, §3.5) not confirmed; appears to make those keys unrestorable.
4. `frag_wallet.py` warns that older 8-line fragments may be incompatible with current ones; the
   older coefficient derivation is not in the repo, so "Version 0" restore compatibility cannot be
   verified beyond the parsing rules in §4.8.
5. Recovery-tool counts in §9.3 depend on full wallet-file semantics (other spec); not ported.
