# Armory Rust rebuild

Planning and specification documents for rebuilding Armory in Rust for Fedora Linux and macOS, with a CLI and TUI
in place of the PyQt4 GUI.

1. [00-feature-evaluation.md](00-feature-evaluation.md) sorts every legacy feature against today's Bitcoin protocol and
   Bitcoin Core into keep, redesign, drop or new, maps each to its CLI/TUI command, and lists the open decisions.
2. [01-architecture.md](01-architecture.md) is the architecture decision record: workspace layout, backend, security
   rules, compatibility contract, testing and milestones.
3. [02-modern-wallet-format.md](02-modern-wallet-format.md) is ADR-002: the modern v2 wallet (BIP39/BIP84/BIP86, Argon2id + XChaCha20-Poly1305) and migration of v1.35 wallets.
4. `specs/` holds byte-level specifications of the legacy formats and behaviour, with `file:line` citations:
   - [01 wallet format & crypto](specs/01-wallet-format-and-crypto.md)
   - [02 backups & recovery](specs/02-backups-and-recovery.md)
   - [03 transactions & signing](specs/03-transactions-and-signing.md)
   - [04 lockboxes & multisig](specs/04-lockboxes-multisig.md)
   - [05 blockchain backend & network](specs/05-blockchain-backend-and-network.md)
   - [06 feature inventory (394 rows)](specs/06-feature-inventory.md)
   - [07 upstream open issues (163)](specs/07-upstream-open-issues.md)

Supporting assets: `fixtures/legacy/` (golden files) and `tools/legacy-oracle/` (reference vectors from the original
C++ crypto).
