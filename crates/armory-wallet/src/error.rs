use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not an Armory wallet file (bad file magic)")]
    NotAWallet,
    #[error("file is truncated: {0}")]
    Truncated(&'static str),
    #[error("wallet version {0} is older than 1.35 and is not supported")]
    TooOld(u32),
    #[error("unknown network magic {0:02x?}")]
    UnknownNetwork([u8; 4]),
    #[error("wallet ID network byte {id:#04x} does not match the header network ({header:?})")]
    NetworkMismatch { id: u8, header: crate::LegacyNetwork },
    #[error("multisig wallets (header flag bit 2) cannot be opened, as in Armory")]
    MultisigWallet,
    #[error("corrupt record at offset {offset}: {what}")]
    CorruptRecord { offset: usize, what: &'static str },
    #[error("unsupported entry type {0} (OP_EVAL entries were never implemented)")]
    UnsupportedEntry(u8),
    #[error("wallet is watching-only")]
    WatchingOnly,
    #[error("wallet is encrypted and locked")]
    Locked,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("public and private key do not match at chain index {0}")]
    KeyMismatch(i64),
    #[error("chain index {0} is not available")]
    NoSuchIndex(i64),
    #[error("address not in wallet")]
    NoSuchAddress,
    #[error("only imported addresses can be removed")]
    NotImported,
    #[error("wallet file {path} is readable by other users (mode {mode:o}); fix with chmod 600")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("label too long: {0} bytes (max {1})")]
    LabelTooLong(usize, usize),
    #[error(transparent)]
    Crypto(#[from] armory_crypto::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
