# 05 — Blockchain backend and network: audit against current Bitcoin Core

Status: audit plus recommendation. Snapshot: repo HEAD `2a6fc53` (Armory 0.93.3, `armoryengine/ArmoryUtils.py:69`), compared against Bitcoin Core `master` and release notes up to **v31.1**, the latest tag as of 2026-10-01 (`git ls-remote` lists `v31.0` and `v31.1`; there is no `release-notes-32.0.md` yet).

Core sources cited below come from `raw.githubusercontent.com/bitcoin/bitcoin/master/...` and from the `doc/release-notes/release-notes-X.md` files in the same tree. In this document, "Core" means Bitcoin Core.

---

## 0. Executive verdict

| Mechanism | Verdict |
|---|---|
| C++ BDM reads `blk*.dat` directly | **BROKEN.** It has no BIP144 (segwit) parsing, so every mainnet block from height 481,824 onward fails the merkle check. On a block dir created by Core 28 or later, the XOR obfuscation means it finds **zero** blocks. It also requires an unpruned node. |
| Armory's own LMDB (fullnode/supernode) | **OBSOLETE.** Fullnode mode copies every raw block into Armory's own DB (about 700 GB or more today). Its script model only knows P2PKH, P2PK, P2SH and bare multisig. |
| P2P client to localhost:8333 (`Networking.py`) | **DEGRADED, but technically accepted.** Version 40000 is at least `MIN_PEER_PROTO_VERSION` (31800), and the low version protects it from new messages. However, any unknown message (for example `notfound`) permanently stalls the stream, and broadcast gets no rejection feedback. |
| RPC via `SDM.py` | **BROKEN.** It depends on `getinfo` (removed in 0.16) and `estimatefee`/`estimatepriority` (removed in 0.17/0.15). It writes `rpcuser`/`rpcpassword` into the user's `bitcoin.conf`, ignores cookie auth, and cannot parse config sections. |
| Daemon management (launch, guardian, torrent) | **REMOVE.** The bootstrap torrent tracker no longer resolves in DNS, `bootstrap.dat` auto-import was removed in Core 0.20, and the guardian sends SIGKILL to bitcoind 3 seconds after SIGTERM. |
| Network constants | Mainnet and testnet3 values are correct. Testnet3 is deprecated in Core. Testnet4, signet and regtest are unknown to Armory (regtest's magic is mislabelled "Old Test Network"). Bech32/bech32m are absent. |
| Announce/version/update services | **DEAD.** The S3 buckets return `AccessDenied`, the tracker has no DNS record, and the bitcoinarmory.com and Google Code endpoints are obsolete. |
| **Recommendation** | Drop all block-file parsing and P2P. Use a **Core RPC backend**: a descriptor watch-only wallet per Armory wallet, with cookie auth and Core 29 or later. Offer an **Electrum-protocol backend** (electrs/Fulcrum) as the alternative. |

---

## 1. How Armory gets blockchain data today

### 1.1 Overall architecture

```
 bitcoind / Bitcoin-Qt (user-run or launched by SDM.py)
   |  blocks/blk*.dat  (read directly, mmap)         <-- C++ BDM (BlockUtils.cpp)
   |  P2P :8333 localhost (version 40000)            <-- armoryengine/Networking.py (Twisted)
   |  JSON-RPC :8332 (rpcuser/rpcpassword)           <-- SDM.py (status, stop, fee estimate)
   v
 Armory LMDB (ARMORY_HOME_DIR/databases/{blocks,headers,history,txhints})
   v
 BlockDataViewer / BtcWallet / ScrAddrObj / LedgerEntry / HistoryPager  -> SWIG -> Python UI
```

- The configuration is built in Python: `armoryengine/BDM.py:310-347` (`bdmConfig`). It passes `blkFileLocation = <BTC_HOME_DIR>/blocks` and `levelDBLocation = ARMORY_DB_DIR`, plus the genesis hash, genesis tx hash and magic bytes taken from `ArmoryUtils.py`.
- `BDM.py:318-325` **requires `blocks/blk00000.dat` to exist**. A pruned Core node deletes old block files, so Armory refuses to start against one.
- The DB mode comes from `ENABLE_SUPERNODE` (CLI `--supernode`, `ArmoryUtils.py:123,276`): the default is `ARMORY_DB_BARE` and `--supernode` gives `ARMORY_DB_SUPER` (`BDM.py:169-171`).
  - Latent bug: `BlockDataManagerConfig::operator=` hard-resets `armoryDbType = ARMORY_DB_BARE` (`cppForSwig/BlockUtils.cpp:719-734`).
  - The copy constructor delegates to that operator, and the BDM copies the config (`BlockUtils.cpp:893-908`).
  - So `--supernode` appears to be ignored, and every path effectively runs as "fullnode" (non-SUPER).
- The enum in `cppForSwig/BlockDataManagerConfig.h:13-28` lists BARE, LITE, PARTIAL, FULL, SUPER and pruning types. Only BARE/fullnode and SUPER are implemented. The comments at `lmdb_wrapper.h:185-195` say LITE/PARTIAL/pruned are "future" modes.

### 1.2 The block-file reader (`BlockDataManager_LevelDB::BitcoinQtBlockFiles`, `BlockUtils.cpp:76-700`)

- **File discovery.** `detectAllBlkFiles()` (`BlockUtils.cpp:112-146`) enumerates `blk%05d.dat` (`BtcUtils.h:1345-1355`) until a file is missing. Only Core 0.8+ naming is supported. There is no `rev*.dat` or `xor.dat` awareness, and no `-blocksdir` support.
- **Record format assumed.** Each record is `[4-byte magic][uint32 LE size][raw block]`.
  - `readRawBlocksFromFile` (`BlockUtils.cpp:511-595`) mmaps the file and compares the first 4 bytes to `magicBytes_`. On a mismatch it only *logs* "wrong network" (`:529-534`).
  - For every record it checks the magic again. If the magic is wrong it linearly `scanFor`s the next magic (`:549-562`), then hands the raw block to a callback.
  - Headers are read the same way (`readHeadersFromFile`, `:597-670`).
- **Out-of-order blocks.** These come from headers-first sync (Core 0.10+). They are tolerated by reading all headers, organizing the chain in `Blockchain`, and then locating the file position of each header (`getFileAndPosForBlockHash`, `:398-446`; top-block search `:160-300`).
- **Polling.** The BDM thread calls `readBlkFileUpdate()` about once per second (`BDM_mainthread.cpp:409`, `pimpl->inject->wait(1000)` at `:423`). That is how new blocks are detected; nothing is pushed by Core.

### 1.3 Transaction and block parsing (`BtcUtils.h`, `BlockObj.cpp`, `StoredBlockObj.cpp`)

- `BtcUtils::TxCalcLength` (`BtcUtils.h:757-809`) parses `version(4) | varint nIn | TxIn* | varint nOut | TxOut* | locktime(4)`. That is the **pre-BIP144 layout only**.
- `Tx::unserialize` (`BlockObj.cpp:560-570`) sets `thisHash_ = SHA256d(all bytes)`.
- `StoredHeader::unserializeFullBlock` (`StoredBlockObj.cpp:228-327`) parses every tx, recomputes the merkle root, and throws `BlockDeserializingException` on a mismatch (`:320-326`).
- That method is used by both ingest paths:
  - Supernode: `BlockUtils.cpp:1926-1963`.
  - Fullnode scan: `PulledBlock` derives `unserializeFullBlock` (`BlockWriteBatcher.h:138`), and blocks are pulled from LMDB in `BlockWriteBatcher.cpp:336,976,1174-1201`.
- **Script classification** (`getTxOutScriptType`, `BtcUtils.h:884-914`) returns one of `STDHASH160` (P2PKH), `STDPUBKEY65/33` (P2PK), `P2SH`, `MULTISIG` or `NONSTANDARD`.
  - The "scrAddr" key is `prefix byte + hash160`: `0x00` for P2PKH/P2PK, `0x05` for P2SH, `0xfe` for multisig, `0xff` for non-standard (`BtcUtils.h:108-116, 980-1030`).
  - **P2WPKH, P2WSH and P2TR outputs are therefore NONSTANDARD.**
  - `grep -ri "witness\|segwit\|bech32"` over `*.py`, `*.cpp` and `*.h` returns nothing.

### 1.4 LMDB storage schema (`lmdb_wrapper.{h,cpp}`, `StoredBlockObj.h`)

- **Location:** `ARMORY_DB_DIR = ARMORY_HOME_DIR/databases` (`ArmoryUtils.py:406`), overridable with `--dbdir`.
- **Fullnode** (`openDatabases`, `lmdb_wrapper.cpp:366-610`) uses four LMDB environments: `blocks`, `headers`, `history` and `txhints` (`lmdb_wrapper.h:649-652`; DB names at `lmdb_wrapper.cpp:535-538`).
  - The design notes are at `lmdb_wrapper.cpp:418-475`.
  - *Every raw block is copied into Armory's `blocks` DB* (`BlockUtils.cpp:2002-2005` calls `putRawBlockData`).
  - `history` holds TxOuts and spentness only for registered scrAddrs. `txhints` holds hints only for relevant txs.
- **Supernode** (`openDatabasesSupernode`, `lmdb_wrapper.cpp:613+`) uses a single env with `headers` and `blkdata` DBs. Blocks are split into Tx and TxOut rows and every address is indexed.
- **Key prefixes** are the `DB_PREFIX` enum in `StoredBlockObj.h:37-49`: DBINFO, HEADHASH, HEADHGT, TXDATA, TXHINTS, SCRIPT, UNDODATA, TRIENODES, COUNT, ZCDATA. Keys are big-endian `hgtx(4) | txIdx(2) | txOutIdx(2)`; values are little-endian (`lmdb_wrapper.h:53-104`).
- **Zero-conf (ZC):** `ZeroConfContainer` (`BDM_supportClasses.h:231-336`, `.cpp:416-1100`) keeps ZC txs keyed in `DB_PREFIX_ZCDATA` and reloads them at start (`loadZeroConfMempool`).
  - ZC txs reach it only from Python: `ArmoryQt.newTxFunc` calls `TheBDM.bdv().addNewZeroConfTx(raw, time, True)` (`ArmoryQt.py:2613-2617`; armoryd `armoryd.py:3294`).
  - Python in turn gets them from the P2P `tx` message.
- **Wallet layer:**
  - `BtcWallet` registers scrAddrs (prefixed hash160s).
  - `ScrAddrObj` holds TxIO pairs per scrAddr.
  - `LedgerEntry` holds the per-tx net value per wallet.
  - `HistoryPager` pages ledgers for the UI (`BtcWallet.h:57-250`, `ScrAddrObj.h:41-293`, `LedgerEntry.h:56-154`, `HistoryPager.h:18-77`).
  - Python receives callbacks `BDMAction_Ready/NewBlock/ZC/Refresh` (`armoryengine/BDM.py:40-90`, `BDM_mainthread.cpp:342-410`).

### 1.5 P2P client (`armoryengine/Networking.py`)

- **Connection.** There is a single Twisted `ReconnectingClientFactory` to `127.0.0.1:BITCOIN_PORT` (`ArmoryQt.py:2601-2607`; class at `Networking.py:296-392`).
- **Handshake** (`connectionMade`, `:60-85`):
  - `version = 40000` is hard-coded (`:75`, comment "TODO: this is what my Satoshi client says").
  - `services = 0`, user agent `Armory:0.93.3`, `start_height = -1`.
  - There is **no relay byte**, which is the BIP37 field. Core defaults `fRelay=true` when it is absent.
- **Message table** (`PayloadMap`, `:1097-1110`): `ping`, `tx`, `inv`, `version`, `verack`, `addr`, `getdata`, `getheaders`, `getblocks`, `block`, `headers`, `alert` and `reject`.
  - `PayloadPing` ignores the nonce, and **no `pong` is ever sent** (`:588-610`).
  - `notfound`, `pong`, `sendheaders`, `feefilter`, `sendcmpct`, `wtxidrelay`, `sendaddrv2`, `addrv2` and `getaddr` are all unknown.
- **Processing** (`processMessage`, `:183-222`):
  - On `inv`, Armory sends `getdata` for unknown blocks, and for every tx once the BDM is ready (`:188-203`). The inv types used are only `MSG_TX=1` and `MSG_BLOCK=2` (`:422-424`), with no witness flags.
  - `tx` goes to `func_newTx`, which becomes a ZC in the BDM.
  - `block` goes to `func_newBlock` for logging only. Blocks are still taken from `blk*.dat`.
  - `alert` is stored.
  - `startHeaderDL`/`startBlockDL` (`:226-250`) build messages but never send them (dead code).
- **Framing** (`dataReceived`, `:88-172`; `PyMessage.unserialize`, `:458-480`): an unknown command raises `UnknownNetworkPayload`, and the handler just `return`s **without consuming the bytes** (`:120-121`). `recvData` is only advanced on success (`:111`).
- **Broadcast** (`ArmoryQt.broadcastTransaction`, `ArmoryQt.py:3721-3790`; armoryd `armoryd.py:320`):
  - Armory sends an unsolicited `tx` message (`Networking.py:279-293`).
  - After 3 s it sends `getdata` for the same txid. After 15 s it checks whether the BDM saw the tx as a ZC; if not, it shows "Transaction Not Accepted" with a block-explorer link.
  - There is no other acceptance or rejection signal.

### 1.6 RPC and daemon management (`SDM.py`, `bitcoinrpc_jsonrpc/`, `guardian.py`)

- **`findBitcoind`** (`SDM.py:382-475`) searches `PATH`, `/usr/lib/bitcoin/` and `whereis bitcoind`. On Windows it also looks in Program Files and desktop `.lnk` shortcuts.
- **`readBitcoinConf`** (`SDM.py:495-582`):
  - It creates `bitcoin.conf` if missing and `chmod 600`s it.
  - It parses the file as flat `key=value` lines (`:542-552`).
  - **If `rpcuser`/`rpcpassword` are absent it appends them** to the user's `bitcoin.conf`: `rpcuser=generated_by_armory` plus a random base58 password (`:559-574`).
  - The host is forced to `127.0.0.1` (`:582`), and the port is `rpcport` or `BITCOIN_RPC_PORT`.
- **`launchBitcoindAndGuardian`** (`SDM.py:629-677`) runs `bitcoind [-testnet] -datadir=<dir> [-dbcache=500|1000|2000]` and then spawns `guardian.py <armoryPID> <bitcoindPID>`.
  - Guardian polls every 3 s. When Armory dies it kills bitcoind with SIGTERM, **sleeps 3 s, then sends SIGKILL** (`guardian.py:40-56, 91-112`).
- **RPC calls** go through the `AuthServiceProxy` from `http://user:pass@host:port` (`SDM.py:842-850`; `bitcoinrpc_jsonrpc/authproxy.py`, HTTP Basic auth):
  - `getinfo()['blocks']`, `getblockhash`, `getblock(...)['time']` (`SDM.py:853-899`, used by the `getSDMStateLogic` state machine, `:743-840`).
  - `stop` (`:690`).
  - `estimatefee` and `estimatepriority` (`armoryengine/CoinSelection.py:727-760`, through `TheSDM.callJSON`).
- **Bootstrap torrent** (`SDM.py:152-300`, `armoryengine/torrentDL.py`, vendored `BitTornado/`, `default_bootstrap.torrent`):
  - On mainnet only, if `blocks/` is under 6 GB, it downloads `bootstrap.dat` into the Core datadir before launching bitcoind.
  - The torrent is 16.7 GB, created 2014-03-20, with tracker `http://tracker.bitcoinarmory.com:6969/announce`.
- **Announcements** (`announcefetch.py`, `armoryengine/parseAnnounce.py`, `versions.txt`, `ui/UpgradeDownloader.py`):
  - The fetch runs every 30 min from `https://bitcoinarmory.com/announce.txt`, with backup `s3.amazonaws.com/bitcoinarmory-media/announce.txt` (`announcefetch.py:15-31`).
  - On the first fetch, the URL is decorated with version, OS, OS variant and a unique ID (`:218-254`).
  - The digest is a signed block verified against a pinned key (`ARMORY_INFO_SIGN_PUBLICKEY`, `:300-310`). It lists `changelog`, `dllinks` (installer URLs plus SHA-256 for Armory **and "Satoshi"/bitcoind**, `parseAnnounce.py:147-290`), `notify` and `bootstrap.torrent`.

---

## 2. Verdicts against the current protocol and Core contract

### 2.1 Segwit (BIP141/144) in block files — FAIL

- **Evidence.** `TxCalcLength` (`BtcUtils.h:757-809`) has no marker/flag branch.
  - For a BIP144 tx, the byte after `version` is the marker `0x00`, which is read as `nIn = 0`. The flag `0x01` is then read as `nOut = 1`, and the next 8 bytes (the real input count and outpoint) are read as a value.
  - The computed length and hash are wrong, so `calculateMerkleRoot` does not match and `BlockDeserializingException` is thrown (`StoredBlockObj.cpp:320-326`).
- **Consequence.** Every mainnet block at or above `SegwitHeight = 481824` (Core `src/kernel/chainparams.cpp:124`) that contains a witness tx fails in both the supernode and fullnode scan paths. In practice that is all blocks since August 2017.
  - Supernode logs and stores only the header (`BlockUtils.cpp:1933-1963`). Fullnode scans skip the data.
  - Wallet history after 2017 is wrong or missing. Payments *to* Armory's P2PKH addresses inside segwit-containing blocks are also lost.
- Even if parsing were fixed, `txid` hashing needs the stripped serialization, `wtxid` is not modelled, and P2WPKH, P2WSH and P2TR are classified NONSTANDARD (`BtcUtils.h:884-914`). There is no bech32 (BIP173) or bech32m (BIP350) anywhere.

### 2.2 `blk*.dat` XOR obfuscation (Core ≥ 28.0) — FAIL

- **Evidence (Core).**
  - `release-notes-28.0.md:269-271`: "Block files are now XOR'd by default with a key stored in the blocksdir. Previous releases of Bitcoin Core or previous external software will not be able to read the blocksdir with a non-zero XOR-key."
  - `src/node/blockstorage.cpp:1182-1230`: `InitBlocksdirXorKey` writes `blocks/xor.dat`. The key is random on the *first run of a fresh blocksdir* and all zeros for a pre-existing one. `-blocksxor=0` refuses to start if a non-zero key already exists.
  - `DEFAULT_XOR_BLOCKSDIR{true}` (`src/kernel/blockmanager_opts.h:18`). The key size is 8 bytes (`Obfuscation::KEY_SIZE`).
  - Secondary sources: [learnmeabitcoin blk.dat](https://learnmeabitcoin.com/technical/block/blkdat/) and the [28.0 release announcement](https://groups.google.com/g/bitcoindev/c/ao1qzyMvaLo).
- **Consequence for Armory.**
  - `readRawBlocksFromFile` compares the first 4 bytes with the magic (`BlockUtils.cpp:529`) and logs "wrong network". It then `scanFor`s the magic through the whole file (`:549-562`). Because every byte is XOR'd with a rotating 8-byte key, the magic never appears, so the result is **zero blocks and zero headers**.
  - Any node *initially synced* with Core 28 or later is unreadable. Older blocksdirs keep an all-zero key and stay readable, but they still hit 2.1.
  - Upstream has proposed in-place re-obfuscation (PR [#33324](https://github.com/bitcoin/bitcoin/pull/33324)); it is not listed in the 31.0/31.1 release notes.
  - **A Rust rewrite must not read `blk*.dat`.** The on-disk format is explicitly not a public interface.

### 2.3 Pruning — FAIL

- `BDM.py:318-325` requires `blk00000.dat`.
- Pruned Core nodes (`-prune=N`, `src/init.cpp:542`) delete old block files and are incompatible with any design that rescans from raw files.

### 2.4 P2P protocol version 40000 — ACCEPTED (with hazards)

- **Accepted.** Current Core has `MIN_PEER_PROTO_VERSION = 31800` (`src/node/protocol_version.h:18`), and peers below it are disconnected (`src/net_processing.cpp:3874-3879`). 40000 passes. Core's own `PROTOCOL_VERSION` is 70017 (`protocol_version.h:12`).
- **Low version is protective.** Core gates new messages on the common version:
  - `sendheaders` at 70012 or above (`net_processing.cpp:5831`).
  - `feefilter` at 70013 or above (`:5849`).
  - `wtxidrelay` and `sendaddrv2` at 70016 or above (`:3965-3976`; the comment says some implementations reject unknown messages).
  - Feature negotiation at 70017 or above (`:3994`).
  - At version 40000 Armory receives none of these: txid-based `inv` only, legacy `addr` only.
- **Ping.** Below `BIP0031_VERSION = 60000`, Core sends nonce-less pings and sets `m_ping_nonce_sent = 0` (`:5737-5744`). The timeout disconnect requires a non-zero nonce (`:5706-5714`), so Armory's lack of `pong` is **tolerated**.
- **Witness stripping hides segwit on P2P.** Armory requests `MSG_TX`/`MSG_BLOCK`, and Core serializes those `TX_NO_WITNESS` (`:2680, 2791`). ZC txs received over P2P therefore parse correctly, but they carry no witness data, and segwit outputs remain unrecognized.
- **BIP324 v2 transport** has been the default since Core 27.0 (`release-notes-27.0.md:70-71`). Inbound v1 connections are still accepted, so Armory's v1 connection works.
- **Hazard 1: stream stall.**
  - `notfound` is not in `PayloadMap`. Core sends `notfound` for a `getdata` it cannot serve (`:2830`).
  - `FindTxForGetData` only serves a mempool tx if it was in the mempool before Core's last `inv` to that peer (`:2739-2760`). Inbound inv trickle averages 5 s (`:170`).
  - Armory's post-broadcast `getdata` fires after 3 s (`ArmoryQt.py:3790`, `callLater(3, ...)`), and every tx inv is answered with a `getdata`.
  - `notfound` replies are therefore expected. Because of the non-consuming `return` (`Networking.py:120-121`), **one `notfound` freezes the connection forever**: every later `dataReceived` re-parses the same bytes.
- **Hazard 2: no broadcast feedback.**
  - BIP61 `reject` was removed in Core 0.20 (`release-notes-0.20.0.md:64-100`), so `PayloadReject` never fires.
  - While Core is in IBD, unsolicited `tx` messages are silently dropped (`net_processing.cpp:4714-4716`).
  - The "Not Accepted" heuristic (15 s ZC check) is the only signal.
- **Hazard 3: no listening.** If the user runs Core with `listen=0` (or other settings that disable inbound connections), the P2P connection fails.
- **Alert.** The `alert` system was removed in Core 0.13 (`release-notes-0.13.0.md:282`), so `PayloadAlert` is dead code.
- **Verdict.** Do not port. A rewrite needs neither inbound P2P nor a custom P2P stack. Use RPC (`sendrawtransaction`, `testmempoolaccept`) plus ZMQ or `waitfornewblock` for notifications (§4).

### 2.5 RPC usage — FAIL

| Call | Where | Status in current Core |
|---|---|---|
| `getinfo` | `SDM.py:857` (SDM state machine) | **Removed in 0.16** (`release-notes-0.16.0.md:169-173`). Use `getblockchaininfo` / `getnetworkinfo`. Because the call always throws `JSONRPCException`, the SDM state machine (`:743-840`) can never report "synchronized". |
| `estimatefee` | `CoinSelection.py:732` | **Removed in 0.17.** v0.17 `src/rpc/mining.cpp:766-768` throws "estimatefee was removed in v0.17". Use `estimatesmartfee` (`src/rpc/fees.cpp:45`; default mode `economical`). |
| `estimatepriority` | `CoinSelection.py:749` | **Removed in 0.15**, together with coin-age priority and free transactions (`release-notes-0.15.0.md:171-180`). The caller's `-1` handling is also inverted (`:752-753`). |
| `getblockhash`, `getblock`, `stop` | `SDM.py:690, 858-859` | Still present. |
| Account RPCs, `importaddress`, `importpubkey` | not used by Armory | Account RPCs were removed in 0.18 (`release-notes-0.18.0.md:343`). `importaddress`, `importpubkey`, `importprivkey`, `importmulti`, `dumpprivkey` and the others were **removed in 30.0** along with BDB legacy wallets (`release-notes-30.0.md:261-270`). |

- **Fee consequence.** `estimateFee()` always falls back to `MIN_TX_FEE = 10000` sat/kB (`ArmoryUtils.py:147-148`).
  - The size heuristic assumes 180 bytes per P2PKH input (`CoinSelection.py:810-813`).
  - `calcMinSuggestedFees` can still return **0** for "high-priority" txs (`:818-830`). That is unrelayable: free relay has been gone since 0.15.
  - Core's default `-minrelaytxfee` and `-incrementalrelayfee` are now **0.1 sat/vB** (`release-notes-30.0.md:67-70`), and the fee-estimator floor bucket is 0.1 sat/vB (`release-notes-31.0.md:236-242`).
  - `-paytxfee` and `settxfee` were deleted in 31.0 (`release-notes-31.0.md:186-193`).
  - The rewrite must use vbyte-based fee rates from `estimatesmartfee` and must never produce zero-fee txs.

### 2.6 RPC authentication — FAIL (insecure, conflicts with Core defaults)

- Core uses **cookie auth whenever `-rpcpassword` is unset** (`src/httprpc.cpp:253-276`). The cookie file is `<net datadir>/.cookie` with user `__cookie__` (`src/rpc/request.cpp:86-148`). It can be relocated with `-rpccookiefile` (`src/init.cpp:740`) and its permissions set with `-rpccookieperms` (`:741`). Cookie auth has existed since 0.12 (`release-notes-0.12.0.md:166`).
- When `rpcpassword` is set, Core logs a warning: *"The use of rpcuser/rpcpassword is less secure, because credentials are configured in plain text…"* (`src/httprpc.cpp:277-278`). The recommended alternative is `rpcauth=user:salt$hash` (`src/init.cpp:737`).
- Armory's SDM **appends `rpcuser`/`rpcpassword` to the user's `bitcoin.conf`** (`SDM.py:559-574`). That silently turns off cookie auth for every other tool, such as `bitcoin-cli` without a password.
- The parser (`SDM.py:542-552`) does not understand:
  - `[main]`, `[test]`, `[testnet4]`, `[signet]` and `[regtest]` sections (0.17+, `release-notes-0.17.0.md:127-147`; testnet4 section `release-notes-28.0.md:50-52`).
  - `includeconf`, `rpcauth`, `rpccookiefile`, `rpcbind`/`rpcconnect`, `conf=` or `-datadir` overrides.
  - Since 0.18, Core errors on `#` in `rpcpassword` (`release-notes-0.18.0.md:111`).
- **Rewrite rule.** Never write `bitcoin.conf`.
  - Auth order: (1) explicit `--rpc-cookie-file`; (2) `<datadir>/<netsubdir>/.cookie`; (3) explicit user/password from Armory's *own* config or environment; (4) `rpcauth`-style credentials supplied by the user.
  - The cookie is re-read on every reconnect, because it changes at each bitcoind restart.

### 2.7 Daemon management — REMOVE or REDESIGN

- **Downloading bitcoind** came from the signed `dllinks` announce entries and `versions.txt` (`versions.txt:19-28` pins Core **0.8.1** on SourceForge). Those sources are dead (§3), and the scheme bypasses Core's own release signing.
  - Fedora and macOS users should install Core themselves: the Fedora package, `bitcoincore.org` tarballs verified with `SHA256SUMS.asc` and guix attestations, or Homebrew.
- **Launching:**
  - `-testnet` is the only network flag (`SDM.py:633-634`). Core's `-testnet` is now marked deprecated in favour of `-testnet4` (`src/chainparamsbase.cpp:23`).
  - The `-dbcache` heuristics are harmless.
  - The guardian's **SIGKILL 3 s after SIGTERM** (`guardian.py:48-55`) risks killing bitcoind during its dbcache flush. Correct shutdown is the `stop` RPC (or SIGTERM) followed by waiting until the process exits.
  - If launching is kept at all, use a systemd user unit on Fedora or a launchd agent on macOS, or simply detect an already-running node.
- **Bootstrap torrent:** auto-import of `bootstrap.dat` was removed in **Core 0.20** (`release-notes-0.20.0.md:178-180`; `-loadblock=<file>` is required now). The tracker host `tracker.bitcoinarmory.com` **does not resolve** (NXDOMAIN, checked 2026-10-01). The data stops at early 2014 and is irrelevant next to modern IBD with `assumevalid`. Delete it, along with `BitTornado/`.

### 2.8 Network constants — PARTIAL

| | Armory (`ArmoryUtils.py:469-503`, `BtcUtils.h:62-68`) | Core today (`src/kernel/chainparams.cpp`, `src/chainparamsbase.cpp`) |
|---|---|---|
| mainnet magic / P2P / RPC port | `f9beb4d9` / 8333 / 8332 ✔ | `f9beb4d9` / 8333 / 8332 (`:149-153`; `chainparamsbase.cpp:65`) |
| mainnet base58 | `ADDRBYTE 0x00`, `P2SHBYTE 0x05`, `PRIVKEYBYTE 0x80` ✔ | 0 / 5 / 128 (`:176-178`); bech32 HRP `bc` (`:182`) — **missing in Armory** |
| testnet3 | `0b110907` / 18333 / 18332, `0x6f/0xc4/0xef`, subdir `testnet3` ✔ | Same (`:275-303`, `chainparamsbase.cpp:67`). HRP `tb`. **Deprecated:** "Support for testnet3 is deprecated and will be removed in an upcoming release" (`chainparamsbase.cpp:23`; `release-notes-28.0.md:54-56`). |
| testnet4 (BIP94) | **unknown** | magic `1c163f28`, P2P 48333, RPC 48332, subdir `testnet4`, base58 111/196/239, HRP `tb` (`:383-417`; `chainparamsbase.cpp:69`). Added in 28.0. |
| signet | **unknown** | Magic is derived from the challenge (`kernel::GetSignetMessageStart`, `:532`); the default signet is `0a03cf40`. P2P 38333, RPC 38332, subdir `signet` (custom challenges get their own subdir, `chainparamsbase.cpp:39-56`). Base58 111/196/239, HRP `tb`. |
| regtest | `fabfb5da` is mislabelled **"Old Test Network"** in `BLOCKCHAINS` (`ArmoryUtils.py:331`) | magic `fabfb5da`, P2P 18444, RPC **18443**, subdir `regtest`, base58 111/196/239, HRP **`bcrt`** (`:620-678`; `chainparamsbase.cpp:73`) |

- Other hard-coding: `ArmoryUtils.py:1441` hard-codes `'\x6f'` for testnet, and `NETWORKS` (`:334-339`) maps a version byte to a network name. Testnet4, signet and regtest all share the testnet base58 bytes, so **the network cannot be inferred from a base58 address**. The rewrite needs an explicit `Network` enum.
- `NETWORKS['\x34'] = Namecoin` is irrelevant.
- `ARMORY_RPC_PORT` 8225/18225 (armoryd) and the single-instance port `8223` (`ArmoryUtils.py:268`) are Armory-private.

---

## 3. Hard-coded URLs, hosts and services

The list comes from `grep -rnoE "(https?|ftp)://..."` over `*.py`, `*.cpp`, `*.h`, `*.txt`, `*.nsi`, `*.md` and `Makefile`, excluding the vendored `cryptopp`, `urllib3`, `gtest`, `mdb` and `leveldb*` trees and licence URLs. Live probes were run from this sandbox on 2026-10-01. The egress proxy blocked most HTTPS hosts, so a "blocked" result there is *not* evidence that the site is down.

### 3.1 Runtime network calls (functional)

| URL / host | Where | Purpose | Status / classification |
|---|---|---|---|
| `127.0.0.1:8333/18333` (P2P) | `ArmoryQt.py:2605-2607`, `ArmoryUtils.py:471,488,1691` | ZC, broadcast, liveness | Replace with RPC/ZMQ |
| `http://user:pass@127.0.0.1:8332` | `SDM.py:847` | Core RPC | Replace (cookie auth, §2.6) |
| `http://user:pass@127.0.0.1:8225` | `armoryd.py:3242` | armoryd CLI client | Armory-internal; redesign |
| `https://bitcoinarmory.com/announce.txt` | `announcefetch.py:23` | signed announce digest | **Obsolete.** The project moved to goatpig and `btcarmory.com` in 2016 ([issue #341](https://github.com/etotheipi/BitcoinArmory/issues/341), [Bitcoin Wiki](https://en.bitcoin.it/wiki/Armory)). The domain still resolves (Cloudflare) but content could not be verified here; search results suggest a third-party site. A squatter cannot forge announcements (they are signature-checked against a pinned key, `announcefetch.py:300-310`), but the URL decoration **leaks version, OS and a unique ID** (`:218-254`). **Remove.** |
| `https://s3.amazonaws.com/bitcoinarmory-media/announce.txt` | `announcefetch.py:24` | announce backup | **DEAD** (S3 `AccessDenied`) |
| `https://s3.amazonaws.com/bitcoinarmory-testing/testannounce.txt` | `announcefetch.py:30`, `qtdefines.py:48`, `pytest/testAnnounce.py:10` | test announce | **DEAD** (`AccessDenied`) |
| `https://s3.amazonaws.com/bitcoinarmory-releases/` | `release_scripts/dlmap.txt:1`, `release_scripts/README.txt:164` | installer hosting | **DEAD** (`AccessDenied`) |
| `https://bitcoinarmory.com/atiannounce.txt` | `qtdefines.py:50` | announce (Qt) | Obsolete; remove |
| `https://bitcoinarmory.com/versions.txt` | `qtdefines.py:41` | version check | Obsolete; remove |
| `https://bitcoinarmory.com/scripts/receive_debug.php` | `qtdefines.py:42`, POSTed at `qtdialogs.py:624,914` | **uploads the debug log / bug report** | Obsolete and a **privacy risk** if the domain is owned by a third party. **Remove.** |
| `http://tracker.bitcoinarmory.com:6969/announce` | inside `default_bootstrap.torrent` | BitTorrent tracker | **DEAD** (NXDOMAIN) |
| `http://sourceforge.net/projects/bitcoin/files/Bitcoin/bitcoin-0.8.1/...` | `versions.txt:21-23` | bitcoind 0.8.1 download | Obsolete; Core has not used SourceForge for releases in years. **Remove.** |
| `http://google.com`, `http://microsoft.com` | `ArmoryUtils.py:3750,3759` | "is internet available" probe | Plaintext and leaks usage. **Remove**; online status is "can reach the backend". |
| `https://blockchain.info/tx/%s`, `/address/%s`, `/search/%s` | `ArmoryUtils.py:485-486`, `qtdialogs.py:15054`, `ui/MultiSigDialogs.py:1362` | explorer links | Third-party, now rebranded `blockchain.com`. Make it a user-configurable template (default `mempool.space`) or remove; it leaks addresses when clicked. |
| `http://blockexplorer.com/testnet/tx/%s`, `/address/%s` | `ArmoryUtils.py:502-503`, `qtdialogs.py:15051`, `ui/MultiSigDialogs.py:1359` | testnet explorer | Obsolete; make configurable |
| `http://coinbase.com/api/v1/prices/` | `samplemodules/testPlugin.py:167` | sample plugin price | Dead API version; drop with plugins |
| `http://www.satoshidice.com` | `extras/sample_armory_code.py:196` | example | Dead or irrelevant |
| `http://bitsend.rowit.co.uk` | `extras/createTxFromAddrList.py:181` | example | Dead or irrelevant |

### 3.2 Help, links and documentation (UI text only)

- `bitcoinarmory.com/{faq,support,troubleshooting,download,all-about-change,armory-backups-are-forever,using-our-wallet,about/using-lockboxes,announcements,privacy-policy,install-*,building-from-source,armory-and-bitcoin-qt}`:
  - Locations: `ArmoryQt.py:757,2111,3754,4485-4489,5317-5553`, `qtdialogs.py:414-415,668,953,4069,6159,7223,8681,8848,9361,11898`, `ui/MultiSigDialogs.py:698`, `versions.txt:49`, `README.md:76`, `ArmorySetup.nsi:9`, `armoryd.py:21`.
  - Classification: **obsolete**. Replace with the rewrite's own docs.
- `www.bitcoin.org`, `bitcoin.org/en/download`, `bitcoin.org/en/alerts`, `bitcoin.org/en/version-history`, `bitcoin.org/en/developer-reference#estimatefee|#estimatepriority`:
  - Locations: `ArmoryQt.py:1974,4479,4518,5401-5448`, `qtdialogs.py:7573,10793-10894`, `ui/UpgradeDownloader.py:551`, `CoinSelection.py:730,747`.
  - Classification: stale. Point to `bitcoincore.org`. The alerts page and the estimatefee/estimatepriority anchors refer to removed features.
- `bitcointalk.org` threads (`armoryd.py:39,1921`, `CoinSelection.py:617`, `ArmoryQt.py:5432`, `qtdialogs.py:1811`) are historical references.
- `github.com/etotheipi/BitcoinArmory` (`README.md:5`, `versions.txt:2` via raw.github, `extras/findpass.py:242`, `release_scripts/Step1_Online_PrepareForSigning.py:22`) is an archived upstream; the goatpig fork superseded it.
- `chart.googleapis.com/chart?...cht=qr` (`README.md:86`) points at the Google Image Charts QR API, which is deprecated and shut down.
- `en.bitcoin.it/wiki/...` (`ArmoryUtils.py:2207,2216`, `Transaction.py:860`) and Stack Overflow, Python bug tracker and Qt bug tracker comments are references only.

### 3.3 Build, release and vendored code

- `bitcoinarmory.googlecode.com`, `code.google.com/hosting`, `PROJECT.googlecode.com` (`release_scripts/googlecode_upload_release.py:25,35,44,199,325`) are **dead**; Google Code shut down in 2016.
- `osxbuild/build-app.py:306-513` fetches Python, PyPI, Qt 4.8/5.2, SIP/PyQt from SourceForge, WebKit trac, Homebrew bottles and `wiki.phisys.com`. These are pinned to 2014-era versions, and many paths are obsolete (Qt 4 is EOL). They are irrelevant to the Rust build.
- `r-pi/crosscompile.py:17-20` (archive.raspbian.org, python2.7 debs) is obsolete.
- `BitTornado/BT1/makemetafile.py:51-55` contains placeholder tracker URLs (tracker1.com and similar) in help text.
- `pytest/*`, `parseAnnounce.py:153-180` (`http://url/...`, `http://btc.org/...`) and `example.com`/`merchant.com` are test fixtures.

---

## 4. Recommendation for the Rust rewrite

### 4.1 Principle

Armory's value is offline key management, paper and fragmented backups, lockboxes, and coin control. Its block indexer is a liability. The rewrite should:

1. **Never parse `blk*.dat`.** Use XOR'd, prunable files only through Core's public interfaces.
2. **Never speak raw P2P.** Core's RPC, ZMQ and REST are stable and versioned, and Core already provides P2P privacy features such as `-privatebroadcast` (`release-notes-31.0.md:120-134`).
3. Keep its own state small: a cache of wallet history derived from the backend and keyed by txid, plus wallet metadata. **No blockchain copy.**
4. Put the backend behind a trait (`ChainBackend`) with two implementations: **Core RPC** (primary) and **Electrum protocol** (alternative).

### 4.2 Primary backend: Bitcoin Core JSON-RPC with descriptor watch-only wallets

**Wallet model.**
- Each online Armory wallet or lockbox maps to one Core wallet, created with `createwallet name=armory-<walletId> disable_private_keys=true blank=true load_on_startup=true`. Since 23.0 descriptors are the default and the only type (`release-notes-23.0.md:171-173`; legacy wallets cannot be created since 26.0 and are gone in 30.0).
- **Armory 1.x addresses do not use a BIP32 chain.** They come from Armory's chaincode-based derivation, typically with **uncompressed** pubkeys. Ranged `xpub/*` descriptors therefore do not apply. Import each address as an individual descriptor:
  - `pkh(<pubkey hex, 65-byte uncompressed or 33-byte compressed>)` for single-sig P2PKH. Uncompressed keys are valid in `pkh()`; `importdescriptors` accepts `pkh(<pubkey>)` (Core `test/functional/wallet_importdescriptors.py:145-164`).
  - `sh(multi(M,<pk1>,...,<pkN>))` for lockboxes. Use `multi` in Armory's exact key order, not `sortedmulti`, unless the lockbox script sorts its keys.
  - `combo(<pubkey>)` if P2PK outputs to the same key must also be seen.
  - `addr(<address>)` or `raw(<scriptPubKey hex>)` as a fallback for watch-only entries without pubkeys. Both are accepted in descriptor watch-only wallets: Core's legacy-to-descriptor migration produces exactly `addr()`/`raw()` descriptors (`test/functional/wallet_migration.py:951-956,1046-1050`). Note that `addr()`/`raw()` are *not solvable*, so `walletcreatefundedpsbt` cannot estimate input sizes for them. Prefer `pkh()`/`sh(multi())`.
- **Lookahead.**
  - Armory computes the next N addresses (gap ≥ 100) locally and imports them in **one `importdescriptors` batch**, each entry with `{"desc": ..., "timestamp": <wallet birthday or 0>, "label": ...}`.
  - When usage approaches the end of the gap, it imports the next batch with `"timestamp": "now"`, which avoids a rescan because no history can exist yet for unused addresses.
  - `importdescriptors` "will trigger a rescan of the blockchain based on the earliest timestamp" (`src/wallet/rpc/backup.cpp:179-198`).
  - On a **pruned** node, a rescan below the prune height fails. Users restoring old wallets need an unpruned node or the Electrum backend.

**Minimal RPC surface:**

| Need | RPC | Min Core |
|---|---|---|
| Health, network, sync progress, prune state | `getblockchaininfo` (`chain`, `blocks`, `headers`, `initialblockdownload`, `verificationprogress`, `pruned`, `pruneheight`) | 0.9.2 (fields evolved; `getinfo` replacement per 0.16 notes) |
| Node version and relay fee | `getnetworkinfo` (`version`, `subversion`, `relayfee`, `incrementalfee`) | — |
| Create/load watch-only wallet | `createwallet` (`disable_private_keys`, `blank`, `descriptors`), `loadwallet`, `listwallets`, `unloadwallet` | **0.21** for descriptor wallets |
| Register addresses or scripts | `importdescriptors`, `getdescriptorinfo` (checksum), `listdescriptors` | **0.21** (`getdescriptorinfo` 0.17) |
| Balances | `getbalances` (`mine.trusted`, `untrusted_pending`, `immature`; with private keys disabled these are the watch-only totals) | 0.19 |
| UTXOs for coin control | `listunspent` (`minconf`, `addresses`, `include_unsafe`, `query_options`) | — |
| History / ledger | `listtransactions "*" count skip include_watchonly`, `listsinceblock <blockhash>` for incremental sync, `gettransaction <txid> include_watchonly verbose` | — |
| Raw tx / prevouts for signing (offline PSBT or Armory's own unsigned-tx format) | `gettransaction ... verbose=true` (`hex`, `decoded`); `getrawtransaction` only for wallet txs or with `-txindex` | — |
| Pre-flight broadcast check | `testmempoolaccept [rawtx,...]` (gives the reject reason, which replaces the dead BIP61) | 0.17 |
| Broadcast | `sendrawtransaction <hex> [maxfeerate] [maxburnamount]` | — |
| Fees | `estimatesmartfee <conf_target> [economical\|conservative]` in BTC/kvB, converted to sat/vB; floor at `getnetworkinfo.relayfee` | 0.15 |
| Rescan | `rescanblockchain [start] [stop]`, `abortrescan`, `getwalletinfo.scanning` | 0.16 |
| Stateless sweep or "check balance without a wallet" | `scantxoutset start [{"desc": ...}]` (UTXO set only, works on pruned nodes, no history; v28 added `blockhash`/`confirmations`, `release-notes-28.0.md:177-178`) | 0.17 |
| New-block notification | `waitfornewblock [timeout] [current_tip]` long-poll (unhidden and `current_tip` added in 30.0, `release-notes-30.0.md:194-197`) **or** ZMQ `zmqpubhashblock` / `zmqpubrawtx` / `zmqpubsequence` (user must enable them in `bitcoin.conf`) **or** plain polling of `getbestblockhash` every 5-10 s | 0.13 (ZMQ 0.12) |
| Shutdown (only if Armory launched the node) | `stop`, then wait for the process to exit; never SIGKILL | — |
| Optional PSBT path | `walletcreatefundedpsbt`, `decodepsbt`, `finalizepsbt`, `analyzepsbt`, `utxoupdatepsbt` (needs solvable descriptors) | 0.17-0.18 |

**Minimum Core version.**
- The technical floor is **0.21** (descriptor wallets and `importdescriptors`).
- The **supported floor should be 29.0.** With 31.0, versions 28.x and older are End-of-Life (`release-notes-31.0.md:18-19`).
- Developers should test against 29.x, 30.x and 31.x.
- Detect the version via `getnetworkinfo.version` and refuse versions below 210000 with a clear message.

**Connection and auth.**
- Discover the datadir (§5) and the network subdir.
- Read `.cookie`, re-reading it on 401 or after a reconnect.
- Allow `--rpc-url`, `--rpc-user/--rpc-password` or `--rpc-cookie-file` overrides in Armory's own config.
- Use JSON-RPC 2.0, which Core recognizes since 28.0 (`release-notes-28.0.md:66-70`).
- Route wallet calls through `/wallet/<name>`.
- Suggested crates: `bitcoincore-rpc` (or a thin `reqwest`/`ureq` client of our own; the surface is small), `bitcoin` (rust-bitcoin) for tx, PSBT, address and descriptor types, `miniscript` for descriptor strings, and `zmq` as an optional feature.

**What Armory still computes locally:**
- Address derivation (Armory chain and BIP32 for any new wallet type).
- Tx construction and coin selection using vbyte sizes. It must handle P2WPKH/P2TR *destinations* and bech32/bech32m address parsing even if Armory's own wallets stay P2PKH.
- Signing (offline), and lockbox script building.
- The ledger view is derived from `listtransactions`/`gettransaction`. Per-wallet net amounts come from the `details[]` categories; for watch-only wallets this requires `include_watchonly=true` on older versions.

### 4.3 Alternative backend: Electrum protocol server (electrs / Fulcrum / ElectrumX)

- **Protocol:** Electrum Protocol 1.4+ (current docs 1.6.x, [electrum-protocol.readthedocs.io](https://electrum-protocol.readthedocs.io/en/latest/)). Methods used:
  - `server.version`
  - `blockchain.headers.subscribe`
  - `blockchain.scripthash.subscribe` / `get_history` / `listunspent` / `get_balance` (scripthash = SHA256(scriptPubKey), byte-reversed)
  - `blockchain.transaction.get` / `broadcast` / `get_merkle`
  - `blockchain.estimatefee`
  - `blockchain.block.header`
  - Rust crate: `electrum-client`.
- **Why it suits Armory:**
  - Armory's model is "many individual scripts, arbitrary birthday". An address-indexed server answers full history per script **with no rescans and no per-address import**. Restoring a 2013 paper backup becomes instant.
  - It works when the user's Core node is **pruned**, because the server keeps the index. The server still needs an unpruned Core node behind it.
  - It needs no wallet state inside Core, so there is no exposure of `wallet.dat` or multiwallet management.
- **Costs and risks:**
  - The user must run an extra service (electrs about 50 GB of index, Fulcrum more) next to an unpruned Core node.
  - Using a **public** server leaks every address, and the IP, to a third party. The default must be "your own server". Allow TLS and Tor (`socks5h`) and warn loudly on any remote server.
  - Trust: the client should verify merkle proofs (`get_merkle`) against headers it has validated. At minimum it should check PoW and chain continuity of headers from `blockchain.block.headers`.
  - Fee estimates come from the server's Core.
- **Other options considered and not recommended as primary:**
  - BIP157/158 compact-filter light client against a user node with `-blockfilterindex=1 -peerblockfilters=1`. It needs P2P again plus a filter-scanning engine (for example `bip157`/Kyoto-style crates). Possible as a v2 feature.
  - Esplora HTTP API: third-party privacy issues unless self-hosted.

### 4.4 Behaviour that must be redesigned, not ported

| Old behaviour | Replacement |
|---|---|
| BDM full-chain scan into LMDB (`databases/`) | Backend query plus a small local cache (SQLite or sled), rebuildable from the backend at any time |
| P2P `inv`/`tx` for ZC | `listtransactions`/`listsinceblock` polling, or ZMQ `rawtx`, or Electrum `scripthash.subscribe` |
| Broadcast via P2P plus a 15 s "did it appear" heuristic | `testmempoolaccept`, then `sendrawtransaction`; show Core's reject reason verbatim |
| `estimatefee` with a 10 000 sat/kB default and a zero-fee "priority" path | `estimatesmartfee` in sat/vB, never below `relayfee`; user override in sat/vB; RBF (BIP125 / full-RBF default) aware |
| SDM launching bitcoind, editing `bitcoin.conf`, guardian SIGKILL | Detect a running node. Optionally offer a systemd `--user` unit or a launchd plist template. Never write `bitcoin.conf`. |
| Bootstrap torrent, announce fetch, versions.txt, bug-report POST, internet probe | Delete. Release notifications, if wanted at all, should come from an opt-in check against a signed feed the new project controls. |
| Testnet = `--testnet` boolean | `--network {mainnet,testnet3,testnet4,signet,regtest}` driving magic (for display only), ports, datadir subdir, base58 bytes and bech32 HRP |

---

## 5. Data directories

### 5.1 Bitcoin Core defaults (`GetDefaultDataDir`, `src/common/args.cpp:859-880`)

| OS | Default datadir | Notes |
|---|---|---|
| Linux (Fedora) | `~/.bitcoin` | Not XDG. A system service (`contrib/init/bitcoind.service:21-23`) uses `-datadir=/var/lib/bitcoind -conf=/etc/bitcoin/bitcoin.conf`. Its cookie is then `/var/lib/bitcoind/.cookie`, readable only by the `bitcoin` user or group (`-rpccookieperms=group`). |
| macOS | `~/Library/Application Support/Bitcoin` | Same as Armory assumed (`ArmoryUtils.py:314-315`) |
| Windows (reference only) | `%LOCALAPPDATA%\Bitcoin`, new in 28.0; the old `%APPDATA%\Bitcoin` is still used if present (`release-notes-28.0.md:60-64`) | Armory assumed `%APPDATA%\Bitcoin` (`ArmoryUtils.py:291-298`) |

**Network subdirectories** (`src/chainparamsbase.cpp:61-74`):

| Network | Subdir | RPC port | Cookie |
|---|---|---|---|
| mainnet | none | 8332 | `<datadir>/.cookie` |
| testnet3 | `testnet3/` | 18332 | `<datadir>/testnet3/.cookie` |
| testnet4 | `testnet4/` | 48332 | `<datadir>/testnet4/.cookie` |
| signet | `signet/` (custom challenge: `signet_<hash>/`) | 38332 | `<datadir>/signet/.cookie` |
| regtest | `regtest/` | 18443 | `<datadir>/regtest/.cookie` |

`-blocksdir` may move `blocks/` elsewhere. With RPC this no longer matters to Armory.

**Discovery order for the rewrite:**
1. `--bitcoin-datadir` / `--rpc-cookie-file` CLI options.
2. `ARMORY_BITCOIN_DATADIR` environment variable.
3. Armory's config file.
4. The OS default above.
5. On Linux, `/var/lib/bitcoind` if it is readable.

### 5.2 Legacy Armory locations (migration sources)

| OS | Armory home | Contents |
|---|---|---|
| Linux | `~/.armory/` (testnet: `~/.armory/testnet3/`) (`ArmoryUtils.py:305-309`) | `armory_<id>_.wallet`, `armory_<id>_WatchOnly.wallet`, `ArmorySettings.txt`, `armorylog.txt`, `multisigs.txt` (lockboxes), `databases/` (LMDB, **discard**), `bittorrentcache/` (**discard**), announce `*.file` (**discard**) |
| macOS | `~/Library/Application Support/Armory/` (`:313-316`) | same |

### 5.3 Proposed Rust-Armory locations

Wallet files are highest-value secrets. They belong in a data dir (not cache), created `0700` and written with `0600` and atomic renames.

| Kind | Fedora (XDG Base Directory spec) | macOS |
|---|---|---|
| Config (`armory.toml`: backend, network, explorer template) | `$XDG_CONFIG_HOME/armory/` (default `~/.config/armory/`) | `~/Library/Application Support/Armory/config/` |
| Wallets and lockboxes (per network) | `$XDG_DATA_HOME/armory/<network>/wallets/` (default `~/.local/share/armory/mainnet/wallets/`) | `~/Library/Application Support/Armory/<network>/wallets/` |
| History cache (rebuildable) | `$XDG_CACHE_HOME/armory/<network>/` (default `~/.cache/armory/`) | `~/Library/Caches/Armory/<network>/` |
| Logs | `$XDG_STATE_HOME/armory/logs/` (default `~/.local/state/armory/logs/`) | `~/Library/Logs/Armory/` |
| Runtime (single-instance lock/socket) | `$XDG_RUNTIME_DIR/armory/` | `$TMPDIR/armory-<uid>/` |

- Use the `directories` crate (`ProjectDirs::from("", "", "Armory")`) to compute these. On macOS keep the human-readable `Armory` name, which matches the legacy path, so migration on macOS can be in place.
- Allow a single `--datadir` override that puts everything under one root, for portable or offline-USB use. This mirrors the old `--datadir`, `ArmoryUtils.py:394-404`.
- On first run, if `~/.armory` (Linux) or the legacy macOS directory exists and the new wallet dir is empty, offer to **copy** (never move) `*.wallet` and `multisigs.txt`. Ignore `databases/`.
- **Network naming:** use `mainnet`, `testnet3`, `testnet4`, `signet` and `regtest` as subdirectories. Do not reuse the empty-string mainnet convention; it caused Armory's `SUBDIR` special-casing (`ArmoryUtils.py:288`).

---

## Appendix: Core sources consulted

- `src/node/protocol_version.h` (versions), `src/net_processing.cpp` (version handshake, ping, getdata/notfound, tx handling), `src/node/blockstorage.cpp` and `src/kernel/blockmanager_opts.h` (XOR key), `src/init.cpp` (options), `src/httprpc.cpp` and `src/rpc/request.cpp` (auth/cookie), `src/kernel/chainparams.cpp` and `src/chainparamsbase.cpp` (network params), `src/common/args.cpp` (default datadir), `src/rpc/fees.cpp` (`estimatesmartfee`), `src/wallet/rpc/backup.cpp` (`importdescriptors`), `contrib/init/bitcoind.service`, and `test/functional/wallet_importdescriptors.py` / `wallet_migration.py`. All from `https://raw.githubusercontent.com/bitcoin/bitcoin/master/...`.
- Release notes `doc/release-notes/release-notes-{0.12.0,0.13.0,0.15.0,0.16.0,0.17.0,0.18.0,0.20.0,23.0,26.0,27.0,28.0,30.0,31.0}.md`, plus v0.17.0 `src/rpc/mining.cpp` for the `estimatefee` removal stub.
- Web: [Core 28.0 announcement](https://groups.google.com/g/bitcoindev/c/ao1qzyMvaLo), [learnmeabitcoin blk.dat/xor](https://learnmeabitcoin.com/technical/block/blkdat/), [Core v30.0 announcement](https://groups.google.com/g/bitcoindev/c/44rT5evWVxI), [Electrum protocol docs](https://electrum-protocol.readthedocs.io/en/latest/), [etotheipi/BitcoinArmory#341](https://github.com/etotheipi/BitcoinArmory/issues/341), [Bitcoin Wiki: Armory](https://en.bitcoin.it/wiki/Armory).
