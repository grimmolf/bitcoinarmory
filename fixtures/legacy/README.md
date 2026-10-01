# Legacy Armory golden fixtures

Copied verbatim from `pytest/tiab.zip` (`tiab/armory/`, testnet-in-a-box, May 2014).
These are **testnet** files with unencrypted test keys; never use them with real funds.

| File | What it is | Spec |
|---|---|---|
| `armory_{GDHFnMQ2,vzgEfJrJ,DZMmtb2v}_.wallet` (+ `_backup`) | v1.35 legacy wallets, unencrypted, 50 chained addresses verified | `docs/rust-rebuild/specs/01-wallet-format-and-crypto.md` |
| `armory_EyUJNfMQ_.unsigned.tx`, `armory_*_.signed.tx` | USTX ASCII blocks (TXSIGCOLLECT) | `specs/03-transactions-and-signing.md` |
| `Simulfund_fmuHCs5G.sigcollect.tx` | multi-party simulfunding USTX | `specs/04-lockboxes-multisig.md` |
| `Contrib_*_1BTC.promnote` | promissory notes (version 0 in v1 layout) | `specs/04-lockboxes-multisig.md` |
| `multisigs.txt` | 4 lockboxes (2-of-3, 1-of-2, 2-of-2, 4-of-7), version 0 | `specs/04-lockboxes-multisig.md` |

## Encrypted fixtures (`encrypted/`)

Real encrypted v1.35 wallets written by Armory, taken from the successor project
[goatpig/BitcoinArmory](https://github.com/goatpig/BitcoinArmory) at commit `d0294d59` (licensed there under
the ATI AGPL / goatpig MIT terms in that repository's `LICENSE`). Verified in
`docs/rust-rebuild/specs/01a-encrypted-wallet-verification.md`.

| File | Source path | Passphrase | Notes |
|---|---|---|---|
| `FakeWallet123.wallet` | `extras/test/FakeWallet123.wallet` | `FakeWallet123` | random (pre-1.35a) chain code |
| `goatpig-legacy-testnet.wallet` | `cppForSwig/gtest/input_files/legacy.wallet` | `testnet` (`BridgeTests.cpp:3499`) | contains pending records (idx 100-102, created while locked) |
