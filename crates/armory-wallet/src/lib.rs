//! Legacy Armory wallet files (format v1.35) and their backups.
//!
//! See `docs/rust-rebuild/specs/01-wallet-format-and-crypto.md` for the byte layout and
//! `02-backups-and-recovery.md` for paper and fragmented backups.

pub mod error;
pub mod keytext;
pub mod legacy;
pub mod network;
pub mod record;
pub mod store;

pub use error::{Error, Result};
pub use legacy::LegacyWallet;
pub use network::LegacyNetwork;
pub use record::AddressRecord;
pub use store::WalletFile;
