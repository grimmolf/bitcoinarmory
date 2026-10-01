# ADR-002: The modern Armory wallet (format v2)

Status: accepted (owner decision, 2026-10-01: "move to the latest version of the wallets; we want this modernized").
Resolves D-1 and D-2 of [00-feature-evaluation](00-feature-evaluation.md).

## Decision

New wallets use standard, interoperable key derivation, stored in a new versioned Armory file:

| Aspect | Choice |
|---|---|
| Seed | BIP39 mnemonic (24 words by default, 12 allowed) with optional BIP39 passphrase |
| Keys | BIP32 |
| Default account | BIP84 native SegWit, `wpkh([fp/84h/coin'/0h]xpub/<0;1>/*)`, addresses `bc1q…` |
| Optional account | BIP86 Taproot, `tr([fp/86h/coin'/0h]xpub/<0;1>/*)`, addresses `bc1p…` |
| Legacy funds | A **legacy-1.35 account** inside the same file (root key + chain code migrated from a v1.35 `.wallet`), P2PKH, spendable and sweepable |
| Coin type | 0 on mainnet, 1 on testnet3/testnet4/signet/regtest |
| Wallet ID | BIP32 master key fingerprint (8 hex chars), the identifier every other wallet shows |
| Interop | Public and private descriptors with BIP380 checksums, ready for `importdescriptors` and other wallets |
| File | `<id>.armory` JSON, plus `<id>.armory.bak`; mode 0600; atomic writes |
| Encryption | Secrets (seed entropy, BIP39 passphrase, legacy roots, imported keys) sealed with **XChaCha20-Poly1305** under an **Argon2id** key (default m = 256 MiB, t = 3, p = 1, parameters stored per file). The header (format, version, network, ID) is bound as associated data. |
| Public data | xpubs, address indexes, labels and comments stay readable so receiving and balance checks never need the passphrase (same property as Armory 1.35 "pending" keys) |
| Watching-only | The same file with no secrets section |

Paper and fragmented backups (D-2) keep Armory's Easy16 line format, applied to the 16/32-byte BIP39 entropy,
and new fragment sets use CSPRNG coefficients. The 24 words are also shown, so any BIP39 wallet can restore.

## Migration

`armory wallet migrate <legacy-id>` (or a path to a `.wallet` file):

1. unlocks the v1.35 wallet and verifies its key chain;
2. creates a new modern wallet (new mnemonic) **or** adds to an existing one (`--into <id>`);
3. adds a `legacy-1.35` account holding the root private key and chain code, the highest-used index, address and
   transaction comments, and imported keys;
4. never modifies or deletes the original `.wallet` file.

Funds on legacy addresses stay where they are until the user sweeps them into the BIP84 account (spending
milestone M4: `armory wallet sweep-legacy`).

## Consequences

- The legacy v1.35 reader and writer stay in the code base as the migration path and for byte-compatible handling
  of old files (`armory legacy ...` commands). They are no longer the default for new wallets.
- goatpig 0.97 `.lmdb` wallets (the last format of the successor project) are a separate import job on the
  roadmap; the format encrypts public data too and needs its own spec.
- Descriptor-based wallets map directly onto Bitcoin Core watch-only descriptor wallets (M3), with ranged
  `wpkh`/`tr` descriptors instead of one descriptor per address.
