/// Errors raised by the legacy primitives.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("invalid secp256k1 key")]
    InvalidKey,
    #[error("invalid character {0:?}")]
    InvalidCharacter(char),
    #[error("checksum error that cannot be corrected")]
    Uncorrectable,
    #[error("finite field error: {0}")]
    FiniteField(&'static str),
    #[error("invalid KDF parameters: {0}")]
    KdfParams(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
