# 07 — Upstream Open Issues Triage (etotheipi/BitcoinArmory)

Status: draft triage for the Rust rewrite (CLI + TUI, Bitcoin Core JSON-RPC backend, Fedora Linux + macOS).
Scope: every **open** issue on <https://github.com/etotheipi/BitcoinArmory/issues>, plus a short note on the successor repository (goatpig/BitcoinArmory).

## 1. Method, date, coverage

* **Date reviewed:** 2026-10-01.
* **Count:** **163 open issues reviewed.** That matches the "163" open-issue count in the repository header. Issue numbers are listed in §2. No pull requests are included.
* **How the list was built:** with WebFetch on the public HTML issue list only. The GitHub API was not used. The plain paginated list (`issues?q=is:issue+is:open&page=N`) was fetched, but the fetch tool cut each page off after about 12 of its 25 rows. Pages 1 and 2 both came back partial. To get every issue, the list was re-queried with `created:YYYY-MM-DD..YYYY-MM-DD` date windows. Any window that returned 12 rows, the truncation limit, was split again until each window returned fewer. The boundary days were also re-checked, which recovered #14, #15, #44 and #71. The unique issue numbers were then counted with a script, giving 163.
* **Pages that could not be fetched:** none of the list pages failed outright. However, the full 25-row pages could not be read in one fetch, which is why date windows were used. On the successor repository, the release pages for `v0.95.0` and `v0.96` returned "error while loading", so §4 uses `changelog.txt` instead.
* **Issue bodies:** **78 issues were opened and read individually** (marked **B** in the *Src* column). The other **85 were classified from the title only** (marked **T**). Title-only rows are spam, build or packaging reports, Qt crashes, support questions and other cases where the title settles the classification. Their notes do not claim any content beyond the title.
* **Comments:** the page summariser showed issue bodies reliably, but it may drop comment threads. It reported no comments or maintainer replies for any issue fetched. Classifications therefore rest on the issue **bodies**, and "no maintainer reply seen" means none showed up in the fetch. It does not prove the thread is empty.
* **Cross-checks against the local 0.93 tree:** a few issues were checked against this checkout to see whether the defect is still present in the code being ported. Each such check is cited as `file:line`. All other "still present?" statements are unverified.

### Categories and dispositions

Categories: **Bug-core** (wallet, crypto or transaction logic) · **Bug-backend** (BDM, LMDB/LevelDB, blk parsing, bitcoind sync and connection) · **Bug-GUI** · **Bug-platform** (Windows, OSX or Linux packaging and build) · **Feature** (feature request) · **Support** (support or question) · **Spam** (spam or noise).

Dispositions:
* **Must** = must address in the Rust design. The row says what the Rust version must do.
* **Obsolete** = obsoleted by design. The row says why.
* **Consider** = feature to consider for the roadmap.
* **N/A** = not applicable: support, spam or out of scope.

## 2. Full table of open issues (163)

| # | Title | Cat | Disp | Notes / Rust requirement | Src |
|---|---|---|---|---|---|
| #9 | Lost receive address after client restart, balance lost etc. | Bug-core | Must | Reported on v0.82: a new receive address and its tx vanished after a restart, then came back on the 3rd restart. **Rust:** persist new addresses (address-pool high-water mark) atomically with fsync *before* showing them. The ledger must be deterministic across restarts. Test: kill the process right after `receive`, restart, and check the address is still there. | B |
| #12 | Resend unconfirmed transactions | Feature | Must | The user asks for 0-conf txs to be rebroadcast on each new block. **Rust:** Core does not rebroadcast txs pushed with `sendrawtransaction` unless they belong to its own wallet. Keep a local "own unconfirmed tx" table. On each new block, check `getmempoolentry`. If the tx is gone and still valid, re-submit it, and say so in the UI. | B |
| #13 | Unable to add a new block to the blockchain | Bug-backend | Obsolete | `parseNewBlockData did not get enough data` on v0.81. Armory's own block parsing is dropped, and Core validates and serves blocks. | B |
| #14 | Armory lost an orphaned transaction | Bug-backend | Must | A tx in an orphaned block disappeared instead of going back to unconfirmed. **Rust:** on a reorg (block hash at a stored height changes), un-confirm txs from the disconnected blocks. Re-check them against the mempool, and drop them only when they are neither in the mempool nor in the new chain. Needs a regtest reorg test (`invalidateblock`). | B |
| #15 | Exception when deleting a wallet | Bug-GUI | Obsolete | KeyError on a stale wallet ID in the Qt systray code. The tray is gone. Lesson for the TUI: removing a wallet must purge every view and notification subscriber (add a test). | B |
| #16 | Unrecognized standard script | Bug-core | Must | P2PKH spends with **compressed** pubkeys were shown as "Unrecognized". **Rust:** the script classifier must recognise P2PK/P2PKH with 33- and 65-byte keys, P2SH, bare multisig and (for display) segwit types. Unit-test it against tx `d035f3af…fe91`. | B |
| #19 | Hey, I just met you, and this is crazy... | Spam | N/A | Announcement that Armory was cross-compiled for Raspberry Pi. Not a defect. | B |
| #20 | Passwords or wallet names with letters ä, ö or å not accepted. | Bug-core | Must | Reported on v0.82.2: wallet creation crashes when the passphrase or name contains non-ASCII text. **Rust:** labels and names are UTF-8 end to end. Passphrases need a defined byte encoding: UTF-8, plus a chosen Unicode normalisation that is documented. It must reproduce what legacy Python 2 Armory hashed, so existing wallets with non-ASCII passphrases still unlock. Add test vectors. | B |
| #21 | Segmentation fault on startup | Bug-backend | Obsolete | Title only. A 2012 segfault implies the C++ layer, which is replaced. | T |
| #22 | Transaction was not accepted by the Satoshi client | Bug-backend | Must | The "not accepted" error appeared even though the tx later confirmed. **Rust:** take the broadcast result from the `sendrawtransaction` reply (txid, or reject code and reason) and run `testmempoolaccept` first. Do not infer failure from a missing P2P echo. | B |
| #23 | Enforced physical protection | Feature | Consider | Asks for paper backups without branding, encrypted paper data, no plaintext temp files during printing/CUPS, and secure deletion. SecurePrint in 0.93 covers encryption. **Rust:** render backups without writing plaintext temp files (stdout or in-memory). Offer an "unbranded" layout. | B |
| #26 | Bitcoins associated with wrong address (display issue) | Bug-core | Must | After confirmation, the funds were credited to a *different* address; a restart fixed it. **Rust:** attribute each output to an address from its scriptPubKey → address map, never from cached UI rows. Test that a payment to a newly created address is attributed correctly without a restart. | B |
| #28 | Delete comment in transaction & restore "auto" comment | Feature | Consider | Clearing a comment should bring back the automatic label. Cheap: treat an empty comment as deletion. | B |
| #30 | Armory repeatedly losing and re-establishing connection with bitcoin-qt | Bug-backend | Must | After about 24 h, disconnect/reconnect notices appeared every 5–10 s. **Rust:** RPC health checks with exponential backoff. Debounce state changes, emitting one notice per transition. Keep a single client instance. | B |
| #34 | Transaction to SatoshiDice not accepted by network ?? | Bug-core | Must | A 0.01 BTC send was repeatedly rejected; the body gives no root cause (dust, fee or standardness are guesses). **Rust:** run `testmempoolaccept` before broadcast and show Core's exact reject reason (e.g. `dust`, `min relay fee not met`). | B |
| #39 | Passphrases don't accept extended ascii chars | Bug-core | Must | Same class as #20: "é" and similar characters make wallet creation loop back to the passphrase dialog. **Rust:** same requirement as #20, plus a round-trip test (create → lock → unlock) with non-ASCII passphrases. | B |
| #40 | Feature Request: Watch balances of bitcoin addresses without needing the private key | Feature | Consider | Watch-only import of bare addresses (paper wallets, Casascius). With Core this maps to watch-only descriptors (`addr(...)`) plus `scantxoutset`/rescan. | B |
| #44 | Feature Request: Possiblity to securely transfer unsigned transactions between online and offline wallet | Feature | Consider | Move unsigned and signed txs over QR to avoid USB. **Rust:** keep the text-armored format first-class (paste-able). Animated QR in the TUI could be a later feature. | B |
| #45 | Feature Request: Make Advanced Encryption Options available on Paper Backup restoration | Feature | Must | Restore does not offer the KDF options that create does. **Rust:** `restore` takes the same KDF and encryption options as `create` (target time, memory). Cheap to provide. | B |
| #46 | Error when i sending bitcoin | Bug-core | Must | "SelectCoins returned a list of size zero" when sending 0.5 from a 0.517 balance, while 0.4 worked. **Rust:** coin selection must work near the full balance once fees are added. On failure, give a typed error ("need X incl. fee Y, have Z"). Provide "send max" (subtract fee from amount). Property-test selection. | B |
| #49 | Running BitcoinArmory on Mac OS | Support | N/A | Title only. macOS support is a goal of the rewrite in any case. | T |
| #52 | OSX: Unexpected termination on incomming TX | Bug-platform | Obsolete | A Growl notification helper crashed the app. Qt and Growl are dropped. Desktop notifications in Rust must be optional and must fail silently. | B |
| #55 | The package is of bad quality | Bug-platform | Obsolete | Title only. Concerns the legacy distro package. | T |
| #57 | Memory leak: Scanning block chain takes 1.7GB RAM | Bug-backend | Obsolete | Title only. The C++ BDM scan is replaced by Core RPC. | T |
| #59 | Scanning blockchain stopped at 230711 | Bug-backend | Obsolete | Title only. C++ BDM. | T |
| #62 | Multi-sig Transactions | Feature | Must | Asks for multisig support. 0.92+ added it as lockboxes, so the issue is stale. Already in porting scope (spec 04). | B |
| #63 | Make it possible to run Armory with RPC back-end. | Feature | Must | This **is** the rewrite's architecture. **Rust:** must support a *remote* Core node (host, port, cookie or `rpcauth` user/pass, wallet-less operation), not only localhost. Document running over an SSH tunnel or WireGuard, because Core RPC has no TLS. | B |
| #67 | Scanning transaction history hangs at 96%, python 100% CPU | Bug-backend | Obsolete | Title only. Legacy scan. | T |
| #69 | Unable to Locate bitcoin-qt.exe when not installed on system drive | Bug-platform | Obsolete | Title only. Windows, and bitcoind discovery/launch is removed (spec 05). | T |
| #70 | Crash when making transaction if not installed on system drive | Bug-platform | Obsolete | Title only. Windows install-path issue. | T |
| #71 | Clicking bitcoin: URI link tries to open new Armory instance | Bug-GUI | Must | Seen on Ubuntu: a second instance launched by a URI broke the first one's Bitcoin-Qt connection. **Rust:** the single-instance lock must be checked *before* any backend I/O, and a second process must exit without side effects. Accept BIP21 URIs as CLI arguments (`send --uri`). | B |
| #72 | Transaction History scanned at every startup | Bug-backend | Must | Full rescan on every start. **Rust:** persist a sync cursor per wallet (last processed block height and hash). Resume incrementally, detecting a reorg by checking the stored hash. Never rescan from genesis unless asked. | B |
| #74 | problem when starting Armory | Support | N/A | Title only. | T |
| #75 | All printing of encrypted wallets | Feature | Consider | Printable encrypted backups. 0.93's SecurePrint (`qtdialogs.py:43-45`) partly covers this. **Rust:** port SecurePrint (spec 06). | B |
| #76 | Quits upon access to clipboard. | Bug-GUI | Obsolete | Title only. Qt clipboard. A TUI clipboard (OSC 52 or `pbcopy`/`wl-copy`) must be optional and must not crash if missing. | T |
| #77 | Launch error preventing bitcoind from starting | Bug-backend | Obsolete | Title only. Armory no longer launches bitcoind (spec 05). | T |
| #79 | Armory client hangs when window is moved | Bug-GUI | Obsolete | Title only. Qt. | T |
| #80 | Compilation error in Ubuntu after Makefile change | Bug-platform | Obsolete | Title only. Legacy Makefile/SWIG build. | T |
| #81 | Armory becomes unusable every time I open an info/popup window | Bug-GUI | Obsolete | Title only. Qt. | T |
| #82 | Wallet rename not reflected in "Transactions" filter dropdown | Bug-GUI | Must | Minor. **Rust:** TUI views read wallet labels from one source of truth and refresh on rename. Add a test. | B |
| #85 | Scanning Transaction History stuck? | Bug-backend | Obsolete | Title only. Legacy scan. | T |
| #87 | Can I see my watch-only key on Android? | Support | N/A | Title only. | T |
| #88 | Can't see a transaction made to an address in Armory | Bug-backend | Must | Armory was stuck at block 234436 while Core kept advancing. **Rust:** always show Armory's synced height next to Core's `blocks`/`headers` (`getblockchaininfo`). Flag a stall once the gap is above N blocks for T minutes. | B |
| #89 | Console error Log: BitcoindNotAvailable | Bug-backend | Obsolete | Title only. Legacy SDM. The Rust "Core unreachable" path is covered under #30/#155. | T |
| #90 | Console error Log: UnicodeDecodeError | Bug-GUI | Obsolete | The "©" in the About text failed to decode as ASCII (`qtdefines.py:215`). A Python 2 str/unicode problem that Rust strings remove. | B |
| #92 | Tag for 0.88.1-beta is missing | Support | N/A | Release-process request. | T |
| #95 | Cannot "Get Keys from Wallet" in message signing window | Bug-GUI | Must | Seen on 0.88.1: an AttributeError in the unlock dialog when the wallet is *encrypted*. **Rust test plan:** message signing must prompt for unlock on encrypted wallets. Cover sign and verify for encrypted and unencrypted wallets. | B |
| #96 | Build instructions use unencrypted git transfer | Bug-platform | Obsolete | Legacy docs. The new docs must use https only. Release artifacts must be signed and have checksums. | T |
| #98 | armoryd.py should accept an array for jsonrpc_sendmany() | Feature | Must | If the armoryd-compatible RPC is kept (spec 06): `sendmany` must accept a JSON object or array of `{address: amount}`, not only the legacy string form. | B |
| #105 | Sourcecode for v0.88.1-beta | Support | N/A | Title only. | T |
| #107 | OSX: build fails to produce a usable binary. | Bug-platform | Obsolete | Title only. Replaced by the cargo build. The macOS CI target must produce a runnable, signed binary. | T |
| #109 | OSX fails to build | Bug-platform | Obsolete | Title only. Same as #107. | T |
| #111 | Synchronization issue between offline and online wallets. | Bug-core | Must | The online watch-only wallet had handed out addresses beyond the offline wallet's computed pool, so signing failed with "not associated with any addresses". **Rust:** the offline signer must derive any chain index referenced by the unsigned tx on demand, up to a sane bound. The unsigned-tx format must carry the chain index or derivation info for each input. | B |
| #113 | Armory seg fault in rescanWalletZeroConf -- txn is not initialized | Bug-backend | Obsolete | C++ zero-conf map (`BlockUtils.cpp`). Lesson: mempool tracking must tolerate missing or partial tx data from RPC. | B |
| #118 | Build fails on Xubuntu 13.10 | Bug-platform | Obsolete | Title only. | T |
| #119 | When there'll be next release? What is the status of `testing` branch? | Support | N/A | Title only. | T |
| #126 | Armory fails to run on OS X 10.9 due to handling of dependencies | Bug-platform | Obsolete | Title only. Python and Qt dependency bundling. | T |
| #127 | Incorrect flagging of valid address as invalid | Bug-core | Must | P2SH address `3M8XGFBK…` was rejected as "unknown network". The 0.93 code appears to accept the P2SH prefix (`ArmoryUtils.py:2137-2145, 2766`), but this was not run. **Rust:** the address parser accepts P2SH (and bech32/bech32m) for the active network and rejects other networks with a clear message. Use this address as a test vector. | B |
| #131 | Armory hangs when trying to import encrypted private key | Bug-core | Consider | BIP38 EC-multiply (two-factor) import hung after the first key. 0.93 has no BIP38 code (no matches in the tree), so this is a feature request in practice. If added: run scrypt off the UI thread with progress, and use the official BIP38 test vectors. | B |
| #132 | Armory High Memory Usage | Bug-backend | Obsolete | Title only. C++ BDM memory. | T |
| #133 | Provide signed source code and changelog of 0.89.99.16-testing | Support | N/A | Release-process request. The rewrite should publish signed tags and a changelog. | T |
| #137 | Version 088.1-beta is online,sync'd etc but Help/ArmoryVersion,,, says offline. | Bug-GUI | Obsolete | Title only. The phone-home version check is not ported (the successor removed it in 0.94; §4). | T |
| #138 | Where did headerObj.getTxRefPtrList end up? | Support | N/A | Title only. Developer API question. | T |
| #140 | Unexpected error in log | Support | N/A | Title only. | T |
| #141 | launching armory destroys cache | Bug-platform | Obsolete | Startup runs `find $HOME` (command-injection risk; trashes the page cache). Still present in 0.93 (`ArmoryQt.py:1452-1454`, building a shell string from `home`). The Firefox `mimeTypes.rdf` registration is dropped. General rule for Rust: never shell out with interpolated paths. | B |
| #142 | how off line armory creates addresses without internet conection? | Support | N/A | Title only. | T |
| #143 | Armory 0.9 for Windows stores blocks in C:/ even after changing settings | Bug-platform | Obsolete | Title only. Windows and the legacy block database. | T |
| #144 | Crash on Windows 8.1 | Bug-platform | Obsolete | Title only. Windows. | T |
| #145 | armory fdatasync()s every 60 bytes written | Bug-backend | Obsolete | One fdatasync per 60-byte LevelDB write. LevelDB is dropped. Lesson: the Rust wallet and cache store must batch writes into transactions and fsync at commit points only. | B |
| #146 | queue empty exception on exit | Bug-backend | Obsolete | Title only. Python BDM thread queue. | T |
| #147 | SegFault during startup in BlockUtils | Bug-backend | Obsolete | Title only. C++ BDM. | T |
| #153 | (ERROR) ArmoryQt.py:4527 - Error in checkSatoshiVersion | Bug-backend | Obsolete | Title only. Replaced by a Core version check through `getnetworkinfo` (spec 05). | T |
| #154 | Error on Armory launch | Support | N/A | Title only. | T |
| #155 | No way to switch from offline to online? | Bug-backend | Must | If Armory starts before the network is up, it stays offline until restarted. **Rust:** the backend connection is a state machine that retries in the background and goes offline → online automatically. Also offer a manual `reconnect` action. | B |
| #156 | Problems with "skip online check at startup" | Bug-GUI | Must | The title showed "Offline" while the app was connected, and the version check disagreed. **Rust:** one authoritative online/offline state that every view reads (see #155). | B |
| #157 | Test backup doesn't work? | Bug-GUI | Must | The "test backup" dialog did not label the chain-code field and gave no result. **Rust:** `backup verify` accepts exactly what the printed sheet shows, with the same field names and line grouping for each backup version (1.35a/1.35c, SecurePrint). It always prints an explicit PASS or FAIL and the wallet ID. | B |
| #162 | Custom entropy | Feature | Consider | User-supplied entropy (the successor added card-deck entropy in 0.94; §4). If added: *mix* it into the OS CSPRNG (e.g. HMAC). Never replace the CSPRNG. | B |
| #164 | Reconnect to Bitcoin-QT logic flawed | Bug-backend | Must | Each reconnect attempt opened another socket and exhausted btcd's connection limit. **Rust:** the RPC client closes or reuses connections, bounds its connection pool, and backs off. Test against a node with a low `rpcworkqueue`. | B |
| #166 | Feature Request: Multithreading for Database Building | Feature | Obsolete | No local block database is built. | T |
| #167 | Error importing paper wallet backup | Bug-GUI | Obsolete | A Python NameError (`PyBtcAddress` not defined in `qtdialogs.py`) on a Raspberry Pi build. Python-specific. The paper-restore round trip is still covered by the #157 tests. | B |
| #168 | Problem importing priv keys | Bug-core | Must | One of four Multibit-exported keys would not import. The cause is not stated; possibly compressed-key WIF (see #190), but this is unconfirmed. **Rust:** key import must accept every common WIF and hex form and say exactly why a key is rejected. | B |
| #170 | ArmoryQT crashes when building Databases | Bug-backend | Obsolete | Title only. | T |
| #171 | Armory crashes when scanning transactions with lots of addresses, transactions | Bug-backend | Obsolete | Title only. C++ scan. Keep a scale test: a wallet with thousands of addresses and txs synced through RPC. | T |
| #172 | Armory fails to start bitcoind | Bug-backend | Obsolete | Title only. Launching bitcoind is removed (spec 05). | T |
| #173 | Armory does launch crazy sh command | Bug-platform | Obsolete | Same `find … mimeTypes.rdf` as #141. | B |
| #174 | Requirement missing for armoryd.py | Bug-platform | Obsolete | Title only. Python dependency. | T |
| #175 | Armory version 0.90.0.0 (beta) crashing | Bug-backend | Obsolete | Title only. 0.90 was the new-BDM release; treating this as a backend crash is an assumption. | T |
| #176 | Armory .90 BETA is unusable | Bug-backend | Obsolete | Title only. Same caveat as #175. | T |
| #177 | Provide 0.90-beta changelog | Support | N/A | Title only. | T |
| #181 | Endlessly Initializing Bitcoin Engine | Bug-backend | Obsolete | Title only. Legacy SDM/BDM startup. | T |
| #183 | UI missing feature: info when press "create unsigned transaction" if not executed | Bug-GUI | Must | No feedback when unsigned-tx creation fails with unconfirmed txs pending. **Rust:** every tx-build failure returns a typed error with a message and a non-zero CLI exit code (e.g. "inputs unconfirmed", "insufficient confirmed funds"). | B |
| #187 | Ubuntu Desktop Icons Disappear | Bug-platform | Obsolete | Title only. | T |
| #188 | Armory does not search for bitcoind (v0.9) in right place on Windows 64bit | Bug-platform | Obsolete | Title only. Windows; bitcoind discovery removed. | T |
| #190 | Can't recognize Compressed keys | Bug-core | Must | **Still present in 0.93:** compressed keys are rejected (`ArmoryUtils.py:2874` raises `CompressedKeyError`; `PyBtcAddress.py:173` says "Armory wallets (v1.35) do not support compressed keys"; `qtdialogs.py:3130-3135`). **Rust:** import and sweep compressed WIF keys. The legacy v1.35 file has no compressed flag, so either sweep only, or store such keys in a new-format record. This is a wallet-format decision. | B |
| #191 | Wallet doesn't correctly recognize transactions to same wallet. | Bug-core | Must | A 10 BTC self-send split over 4 addresses showed 7.5 BTC. **Rust:** define ledger semantics for self-sends (value = sum of outputs back to the wallet; net = −fee) and test them with multi-output self-sends. | B |
| #192 | Export Transactions doesn't correctly display transactions to self. | Bug-core | Must | The CSV export has no self-send marker and no fee. **Rust:** the CSV has a fee column, a direction value (in/out/self) and credit/debit columns. | B |
| #194 | Armory is spaming port 8332 | Bug-backend | Must | Too many connection attempts to RPC port 8332. **Rust:** rate-limited polling. Prefer ZMQ `hashblock` or `waitfornewblock` long-poll, as in spec 05. | B |
| #197 | Race Condition during initial startup. | Bug-GUI | Obsolete | A Qt announcement callback ran before `mainDisplayTabs` existed. The announcement feed and the Qt GUI are both dropped. | B |
| #199 | experiencing issues on website, whether IE or Chrome | Support | N/A | Title only. About the project website. | T |
| #200 | Can't open. Armory keeps on crashing after sync to network | Bug-backend | Obsolete | Title only. | T |
| #201 | terminate called after throwing an instance of 'std::bad_alloc' | Bug-backend | Obsolete | Title only. C++ out of memory. | T |
| #202 | Could you explain these variables | Support | N/A | Asks about `MAGIC_BYTES`, the genesis hash, `ADDRBYTE`/`P2SHBYTE`/`PRIVKEYBYTE`, and hex vs binary byte order (for an altcoin port). Relevant only as a reminder: a single network-params struct with documented byte order (see #348). | B |
| #204 | Question: key derivation algorithm? | Support | N/A | Asks whether Armory's derivation is a custom scheme or BIP32. Covered by the wallet-format spec, which documents the legacy chained derivation. | B |
| #205 | Feature request: make it possible for users to copy/paste or export Public Key + Chain Code | Feature | Consider | Export root pubkey and chain code as one string for watch-only services. 0.93 has the data (`PyBtcWallet.getRootPKCCBackupData`, `:1260`). Offer a `export-watch-data` string. | B |
| #207 | Unable to open settings dialog in 0.91.1 | Bug-GUI | Obsolete | Title only. | T |
| #209 | Import from armoryengine * error | Bug-platform | Obsolete | Title only. Python packaging. | T |
| #212 | ImportError: /home/lucas/Applications/BitcoinArmory/_CppBlockUtils.so: undefined symbol | Bug-platform | Obsolete | Title only. SWIG/C++ build. | T |
| #214 | ImportError: No module named qrc_img_resources | Bug-platform | Obsolete | Title only. Qt resource build. | T |
| #215 | documentation should not link to online resource | Feature | Consider | Armory targets offline machines, so docs should not depend on the web. **Rust:** ship docs offline (man page, `--help`, bundled docs). | B |
| #217 | Show private keys as QR codes | Feature | Consider | Title only. A TUI QR render is possible; it must sit behind an expert flag with a warning. | T |
| #218 | Use Copy-On-Write to minimize the "double blockchain" disk space requirement | Feature | Obsolete | Title only. There is no second copy of the chain. | T |
| #219 | Moving multisig transactions around via servers or preferably p2p | Feature | Consider | "Similar to copay." Transport for lockbox and multisig txs. Out of initial scope. Pairs with a PSBT import/export decision. | B |
| #220 | Problem reading txs from blockchain | Bug-backend | Obsolete | armoryd on the dev branch: "Requested txref not on main chain (BH dupID is diff)". C++ BDM. | B |
| #226 | Feature Request: Send to stealth address support | Feature | Consider | Title only. Low priority; the modern equivalent is BIP352 silent payments. | T |
| #230 | Feature Request: NameCoin Support | Feature | N/A | Title only. Out of scope (Bitcoin only). | T |
| #231 | Segfault While Building Databases | Bug-backend | Obsolete | Title only. | T |
| #237 | NameCoin Support With Domain Autorenewal | Feature | N/A | Title only. Out of scope. | T |
| #242 | build fails on armhf Linaro machine, Sun compiler flags used | Bug-platform | Obsolete | Title only. Legacy Makefile. ARM Linux is not a rewrite target, though aarch64 macOS is. | T |
| #244 | Read addresses through QR codes and/or NFC? | Feature | Consider | Title only. Low priority for a CLI/TUI. | T |
| #246 | installation of vers 92.3 fails on Ubuntu 14.04 | Bug-platform | Obsolete | Title only. | T |
| #247 | Add fields to CSV export | Feature | Consider | Add the counterparty/own address and the UTXO index to the CSV. Cheap; do it together with #192. | B |
| #248 | No 0.92.3 update for OSX 10.9.5? | Bug-platform | Obsolete | Title only. | T |
| #250 | armoryd.py AttributeError on python 2.6 | Bug-platform | Obsolete | Title only. Python version. | T |
| #251 | Armory crashes on startup if armorycpplog.txt is too big | Bug-backend | Must | An 8 GB `armorycpplog.txt` made startup time out ("BDM was not ready… Waited 20 sec"). The C++ log goes away, but **Rust:** use size-capped log rotation, and never read whole logs into memory at startup. | B |
| #252 | Creating Multiple Lockboxes With Same Public Keys Overwrites Previous Lockbox | Bug-core | Must | Reported on 0.93.3: the second 3-of-5 lockbox with the same keys replaced the first one's name. Cause: the lockbox ID is derived from M, N and the **sorted** pubkey hash160s (`MultiSigUtils.py:80-92`), so the same keys give the same ID. **Rust:** keep the legacy ID for compatibility, detect duplicates on create/import, and refuse or offer to merge or rename explicitly instead of silently overwriting. | B |
| #253 | Crash report in Ubuntu | Bug-platform | Obsolete | Title only. The content was not read, so the crash cause is unknown. | T |
| #254 | Remove Export Key Lists from Standard User View | Feature | Consider | Keep raw key-list export behind an expert flag with a warning that a paper backup is the better choice. | B |
| #255 | make test fails with segfault on v0.92.3 | Bug-platform | Obsolete | Title only. C++ tests. | T |
| #256 | make compile instructions available again | Support | N/A | Title only. Docs request. | T |
| #264 | Automatic comment backup? | Feature | Consider | **High value.** Comments and labels are lost after a paper-backup restore. **Rust:** an encrypted metadata export/import (labels, comments, lockboxes) and possibly an automatic backup path. | B |
| #267 | Missing API feature to import/export lockbox | Feature | Must | armoryd cannot import lockboxes or return the base64 text block. **Rust:** CLI and RPC commands to export and import lockbox text blocks byte-identical to the legacy format (spec 04). | B |
| #269 | Crash when running Armory-0.93.0 from Ubuntu 12.04.4 Live DVD | Bug-platform | Obsolete | Title only. | T |
| #270 | 0.93 Ubuntu Offline Bundle Fail | Bug-platform | Obsolete | Title only. The `.deb` offline bundle is dropped. **Rust:** the release must install on an air-gapped Fedora/macOS machine without network dependencies (a self-contained binary). | T |
| #278 | python-2.7 errors | Bug-platform | Obsolete | Title only. | T |
| #281 | [security feature suggesiton] Should only allow wallet files with restrictive permissions | Feature | Must | Wallet files are created `-rw-r--r--`. **Still true in 0.93:** there is no `chmod`/`umask` in `armoryengine/*.py` or `ArmoryQt.py`. **Rust:** create the wallet and data dir 0700 and files 0600. On open, warn about (or refuse) group- or world-readable wallet files, Tor-style. | B |
| #282 | Icon 'armorytestneticon' for 'armorytestnet.desktop' is missing | Bug-platform | Obsolete | Title only. Linux desktop file. | T |
| #288 | SatoshiDatadir setting is ignored when doAutoBitcoind is false | Bug-backend | Must | **Confirmed in 0.93:** `loadBlockchainIfNecessary()` (`ArmoryQt.py:2524`) never calls `setSatoshiPaths()` (`:2490`), so a configured datadir is ignored unless Armory launches bitcoind. **Rust:** one documented config-precedence order (CLI > env > config > default) for datadir, network, RPC endpoint and cookie path, applied the same way on every code path. | B |
| #291 | Invalid signature when preparing lockbox TX | Bug-core | Must | Seen on 0.93.1/Arch: "Signature in USTXI is not valid / Invalid signature while preparing final tx". It happened twice and re-signing did not help. **Rust:** verify each signature against the exact sighash when it is *added* to the unsigned-tx/lockbox object, report which signer and which input failed, and keep the unsigned-tx serialization byte-stable across export/import. Fuzz and round-trip test multi-party signing. | B |
| #293 | Armory crashes after `BlockDataManager Warning` | Bug-backend | Obsolete | Title only. | T |
| #296 | Unable to use 0.93.1 segmentation fault: not enough memory | Bug-backend | Obsolete | Title only. | T |
| #313 | Error when sending lockbox TX | Bug-core | Must | Two tracebacks: `UnserializeError: Unexpected BLKSTRING` when importing the ASCII block (`MultiSigDialogs.py`), and `IndexError` in `createDERSigFromRS`. The local code (`ArmoryUtils.py:2971-2991`) indexes `rBin[0]` after `lstrip('\x00')`, which raises IndexError if r or s is empty or zero; whether that is this user's cause is not confirmed. **Rust:** a strict armored-block parser with typed errors (wrong block type, bad checksum, truncated). The DER encoder rejects empty or zero r/s, and the finaliser checks every required signature exists before encoding. | B |
| #322 | Releases and Change Logs | Support | N/A | Title only. | T |
| #325 | INFO: Maintainer change - This repo seems to be unmaintained for now | Support | N/A | Title only. Informational. | T |
| #327 | any updates to the wallet? | Support | N/A | Title only. | T |
| #328 | armory_0.93.3_ubuntu-64bit.deb fails to install on Linux Mint KDE edition 17.3, is corrupt | Bug-platform | Obsolete | Title only. | T |
| #329 | Armory 0.95.1 DB version mismatch | Bug-backend | Obsolete | A successor-era ArmoryDB upgrade on OS X ("DB version mismatch. Use another dbdir!"). Lesson: version any Rust local cache schema and rebuild it automatically, rather than asking the user to change directories. | B |
| #331 | exporting xpub? | Feature | Consider | "how can I export xpub?" Legacy Armory chains are not BIP32, so legacy wallets have no xpub. Only possible if BIP32/descriptor wallets are added. | B |
| #335 | crash "Illegal Instruction (core dumped)" upon new wallet creation (3rd passphrase) | Bug-platform | Must | 0.96 on Xubuntu 14.04 crashed at the KDF step of wallet creation. The cause is not stated; an unsupported CPU instruction in the binary is likely (inference). **Rust:** release builds target baseline x86-64 (no `-C target-cpu=native`) and aarch64-apple-darwin. Test the KDF on old CPUs or under qemu. | B |
| #336 | Crash when loading: 'ascii' codec can't encode character | Bug-core | Must | `UnicodeEncodeError` for u'\xe1' in `loadCppWallets()` (`ArmoryQt.py:2196`, successor 0.96 code) at startup. **Rust:** non-ASCII wallet paths, file names and labels must work. Use `PathBuf`/`OsString` for paths. Add a test with accented and CJK names. | B |
| #337 | Old releases | Support | N/A | Title only. | T |
| #340 | 0.96: Several font/line height/button width glitches on 4k (3820x2160) displays | Bug-GUI | Obsolete | Title only. Qt HiDPI. | T |
| #341 | THIS IS NO LONGER THE REPOSITORY FOR BITCOIN ARMORY | Support | N/A | Points to <https://github.com/goatpig/BitcoinArmory> (see §4). | B |
| #342 | Paper wallet backup font scales to wider than paper width | Bug-GUI | Must | At 175% Ubuntu scaling the printed root-key line ran off the page. **Rust:** generate the paper backup at fixed physical dimensions, independent of terminal or OS scaling (e.g. a PDF/PostScript or fixed-width text template). Test that every line fits on A4 and US Letter. | B |
| #343 | Fresh installation doesn't show buttons to download bitcoin core | Bug-GUI | Obsolete | Title only. Qt first-run wizard. | T |
| #345 | Armory wallet does not read new BTC in address | Bug-backend | Must | An address was created offline and funded *before* Core was installed; once online, Armory did not see the coins. **Rust:** when a wallet is first attached to a node, scan from the wallet's birthday, or from genesis if unknown, using `scantxoutset` or a descriptor rescan. Offer an explicit `rescan --from`. | B |
| #348 | support for regtest | Feature | Must | "Does armory support regtest?" **Rust:** network params for mainnet, testnet3/testnet4, signet and **regtest** (spec 05 notes regtest is mislabelled in 0.93). The integration-test suite runs against a regtest `bitcoind`. | B |
| #355 | Is it possible to rescue wallet from `_wallet.lmdb` file? | Support | Consider | The user has only an `armory_*_wallet.lmdb` (a successor 0.96+ file), not a 0.93 `.wallet`. Unanswered. An importer for successor-format wallets is a roadmap item, not a 0.93 bug. | B |
| #356 | Does Armory's LMDB file contains the private key too? How can I decrypt it and read the LMDB file? | Support | Consider | Same user: a 102 KiB `_wallet.lmdb` showing only `WalletHeader` and an ID. Unanswered. Same disposition as #355. | B |
| #357 | Armory Does Not Start | Bug-platform | Obsolete | 0.96 on Windows: no GUI, log stops at BDM init. Windows and the successor BDM. | B |
| #363 | Satoshi candidate | Spam | N/A | A bare Medium link. | B |
| #364 | All | Spam | N/A | Title only. | T |
| #365 | Hi | Spam | N/A | Title only. | T |
| #366 | My | Spam | N/A | Title only. | T |

### Tallies

These counts are computed from the table above (163 rows).

| Category | Count |
|---|---|
| Bug-core | 18 |
| Bug-backend | 38 |
| Bug-GUI | 18 |
| Bug-platform | 33 |
| Feature request | 28 |
| Support/question | 23 |
| Spam/noise | 5 |
| **Total** | **163** |

| Disposition | Count |
|---|---|
| Must address in Rust design | 44 |
| Obsoleted by design | 72 |
| Feature to consider | 19 |
| Not applicable | 28 |
| **Total** | **163** |

Some "Must" rows are filed as Bug-backend or Bug-GUI upstream, for example #14, #30, #72, #155, #183 and #342. The legacy component is dropped, but the behaviour it got wrong (reorgs, reconnects, sync cursors, error feedback, print layout) is something the Rust CLI/TUI and RPC layer has to get right. Some Bug-core rows are also partly reclassifications: #26 was filed as a display issue, but it concerns how outputs are attributed to addresses.

## 3. Prioritised summary: issues that change the Rust design or test plan

Ordered by risk to user funds or backups first, then correctness, then robustness.

### P0 — backups, keys, wallet format

1. **Fragmented backups (successor advisory, not an open issue).** goatpig 0.96.3 called the Shamir fragment coefficients a vulnerability because they were deterministic. The 0.93 code being ported does the same thing: `SplitSecret` derives coefficients from `HMAC512(secret, 'splitsecrets')` (`armoryengine/ArmoryUtils.py:2595-2601`). **Requirement:** Rust must *restore* legacy deterministic fragments, but *new* fragment sets must use random coefficients plus a set ID, so fragments from different sets cannot be mixed. Document this break from 0.93 behaviour.
2. **#342 paper backup layout:** render at fixed physical size independent of display scaling. Test that every line fits on A4 and US Letter.
3. **#157 backup verification:** `backup verify` accepts exactly the printed fields and grouping for each backup version and prints PASS/FAIL plus the wallet ID.
4. **#20 / #39 / #336 Unicode:** UTF-8 labels and paths, and a defined passphrase byte encoding that reproduces legacy Python 2 behaviour. Include non-ASCII create/lock/unlock and path test vectors.
5. **#190 / #168 / #16 compressed keys:** import, sweep and classify compressed keys. Decide how the v1.35 wallet format (which has no compressed flag) stores them.
6. **#281 file permissions:** wallet dir 0700 and files 0600; warn or refuse on looser permissions.
7. **#9 address persistence:** fsync a new address before showing it; add a crash-after-`receive` test.
8. **#111 offline/online pool drift:** the offline signer derives any chain index named by the unsigned tx; the unsigned-tx format carries the index.
9. **#264 metadata backup** (Consider, but high value): encrypted export/import of comments, labels and lockboxes, because a paper restore loses them.

### P1 — transaction, fee and ledger correctness

10. **#46 coin selection near full balance:** typed "insufficient incl. fee" error, a "send max" mode, and property tests.
11. **#34 / #22 broadcast:** `testmempoolaccept` before `sendrawtransaction`; show Core's exact reject reason.
12. **#12 rebroadcast:** track own unconfirmed txs and re-submit them if they drop out of Core's mempool.
13. **#191 / #192 / #247 self-send semantics and CSV:** define self-send ledger values; the CSV gains fee, direction, address and UTXO index columns.
14. **#26 attribution:** output-to-address attribution comes from scriptPubKey, with a no-restart test.
15. **#127 address parsing:** P2SH (plus bech32/bech32m) accepted per network; use `3M8XGFBKwkf7miBzpkU3x2DoWwAVrD1mhk` as a vector.
16. **#183 errors:** every tx-build failure is a typed error with a non-zero exit code.

### P1 — multisig / lockboxes (spec 04)

17. **#291 invalid lockbox signature:** verify each signature when it is added, name the failing signer and input, keep serialization byte-stable, and round-trip/fuzz test.
18. **#313 lockbox send errors:** strict armored-block parser with typed errors. The DER encoder rejects empty or zero r/s; the finaliser checks every signature is present.
19. **#252 duplicate lockboxes:** keep the legacy ID (M, N, sorted hash160s) and detect duplicates instead of silently overwriting.
20. **#267 / #98 RPC parity:** lockbox import/export commands, and `sendmany` accepting a JSON object or array.

### P1 — backend (Core RPC) behaviour (spec 05)

21. **#63 remote node:** support a non-local Core over RPC (cookie or rpcauth); document tunnelling.
22. **#348 networks:** mainnet, testnet3/4, signet and regtest params; the integration tests run on regtest.
23. **#14 reorgs:** reorged txs go back to unconfirmed. Regtest `invalidateblock` test.
24. **#72 / #345 sync cursor and birthday rescan:** incremental sync from the stored height and hash; first attach scans from the wallet birthday or genesis.
25. **#30 / #164 / #194 / #155 / #156 connection state machine:** one client with a bounded pool, backoff, debounced notices, automatic offline → online, and ZMQ or long-poll instead of tight polling.
26. **#88 sync visibility:** show Armory height next to Core blocks/headers, plus stall detection.
27. **#288 config precedence:** a single documented order (CLI > env > config > default) applied on every path.

### P2 — build, release and robustness

28. **#335 portable binaries:** baseline x86-64 and aarch64-apple-darwin, no `target-cpu=native`.
29. **#270 / #215 air-gapped install:** self-contained binary with offline docs (man page / `--help`).
30. **#251 logs:** size-capped log rotation.
31. **#71 single-instance lock:** checked before any backend I/O; BIP21 URIs accepted on the command line.
32. **#45 restore KDF options** match the create options.

## 4. Successor project: goatpig/BitcoinArmory

Issue #341 (opened 2017-07-11) says: "The active repository is now at: https://github.com/goatpig/BitcoinArmory". Maintainer: goatpig. Copyright lines in the successor README: Armory Technologies, Inc. 2011–2015 and goatpig 2016–2024.

What the successor added after 0.93. Source: `changelog.txt` on the successor's `master` (<https://raw.githubusercontent.com/goatpig/BitcoinArmory/master/changelog.txt>), the repository README (<https://github.com/goatpig/BitcoinArmory>) and the releases page (<https://github.com/goatpig/BitcoinArmory/releases>). The per-tag pages for v0.95.0 and v0.96 failed to load.

| Version (date per changelog) | Changes relevant to the rewrite |
|---|---|
| 0.94.0 (2016-03-27) | DB rewritten (60 GB to under 200 MB, more than 10× faster startup). Detects RBF zero-conf txs. Card-deck entropy at wallet creation. Licence changed to MIT. **Removed** phone-home code, the torrent bootstrap and supernode. |
| 0.95.0 (2016-10-23) | **Client/DB split** into `ArmoryQt` (client) and `ArmoryDB` (server), talking over FCGI. DB modes DB_FULL/DB_BARE. **SegWit read support** (no spending yet). bitcoind RPC cookie authentication. Fee-per-byte in the Send dialog. |
| 0.96 (2017-04-30) | New script types P2SH-P2PK and **P2SH-P2WPKH (nested SegWit)**. C++ wallet code backed by **LMDB**, mirrored to the new format; this is the `_wallet.lmdb` file in #355/#356. Manual and automatic fee/byte. **RBF** creation (sequence `UINT32_MAX-2`) and **CPFP**. nLockTime set to the current height. Autotools build; `armoryqt.conf` / `armorydb.conf`. |
| 0.96.1–0.96.2 (2017) | Default fee raised to 200 sat/B. DB checksums. **SegWit enabled on mainnet.** Supernode mode. OP_RETURN outputs and custom signer in Expert mode. BCH support. armoryd moved to a separate repository. |
| 0.96.3 (2017-09-21) | **Vulnerability fix:** fragmented backups used a faulty Shamir implementation with deterministic coefficients. Coefficients are now random, and fragment sets carry IDs and cannot be mixed. Old deterministic fragments can still be restored. (See §3 item 1; the same code is in this 0.93 tree.) |
| 0.96.4 (2018-03-30) | Fee estimation with `estimatesmartfee` (falls back to `estimatefee`) and conservative/economical profiles. Confirmation target 2–100 blocks. **SegWit lockboxes.** Coin-selection privacy changes. |
| 0.96.5 (2018-12-23) | **Bech32 spending and outputs.** Configurable DB path. Unsigned txs with bech32 outputs are no longer backward-compatible. SecurePrint AES-CBC decryption fix for Windows (MSVC optimisation). |
| 0.97 RC1 (releases page) | Wallet format moved to `.lmdb` with **public and private data both encrypted**. **BIP32/39/44** support in the backend without GUI. DB_BARE is the default. "Compatibility mode" for spending from pre-0.96.5 addresses. README now lists PySide2/6 (Python 3), libwebsockets, capnproto and libbtc as dependencies. |

**Implications for the rewrite.**
* Fragment-backup randomisation (P0 above) is a known flaw in the code being ported.
* SegWit, bech32, RBF/CPFP and `estimatesmartfee` fees are the minimum feature set a modern Armory-compatible wallet needs, and the successor shipped them. The Rust design should plan for them even if parity with 0.93 is the first milestone.
* #355/#356 show that users hold successor `.lmdb` wallets. Importing those is a roadmap item; the 0.97 format encrypts public data too, so its key derivation and encryption would need their own spec.
