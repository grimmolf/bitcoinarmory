//! Byte-exact primitives of the legacy Armory (0.93, wallet format v1.35) code base.
//!
//! Everything in this crate reproduces the behaviour of the original Python 2 / C++
//! implementation, including its quirks, so that wallets, paper backups and fragments
//! created by Armory a decade ago keep working. The specifications with `file:line`
//! references into the legacy tree live in `docs/rust-rebuild/specs/`.
//!
//! No function in this crate performs I/O.

pub mod aes;
pub mod base58;
pub mod chain;
pub mod checksum;
pub mod easy16;
pub mod error;
pub mod hash;
pub mod hmac;
pub mod kdf;
pub mod secureprint;
pub mod shamir;

pub use error::{Error, Result};
