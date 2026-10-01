//! Armory wallets: the modern v2 format (BIP39/BIP32, BIP84/BIP86) and legacy v1.35 files.
//!
//! See `docs/rust-rebuild/specs/01-wallet-format-and-crypto.md` for the byte layout and
//! `02-backups-and-recovery.md` for paper and fragmented backups.

pub mod descriptor;
pub mod error;
pub mod keytext;
pub mod legacy;
pub mod modern;
pub mod network;
pub mod record;
pub mod store;

pub use error::{Error, Result};
pub use legacy::LegacyWallet;
pub use network::LegacyNetwork;
pub use record::AddressRecord;
pub use store::WalletFile;
