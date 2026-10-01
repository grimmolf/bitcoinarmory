//! Network constants used inside legacy wallet files (`ArmoryUtils.py:474-498`).
//!
//! Armory 0.93 only knew mainnet and testnet3. Every newer test network (testnet4, signet,
//! regtest) shares testnet's base58 version bytes, so legacy-format wallets for those networks
//! are written with the testnet magic.

/// The two network identities a v1.35 wallet file can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyNetwork {
    Mainnet,
    Testnet,
}

impl LegacyNetwork {
    /// Header bytes 12..16.
    pub fn magic(self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Self::Testnet => [0x0b, 0x11, 0x09, 0x07],
        }
    }

    pub fn from_magic(magic: [u8; 4]) -> Option<Self> {
        [Self::Mainnet, Self::Testnet].into_iter().find(|n| n.magic() == magic)
    }

    /// P2PKH version byte (`ADDRBYTE`), also the last byte of the 6-byte wallet ID.
    pub fn p2pkh_byte(self) -> u8 {
        match self {
            Self::Mainnet => 0x00,
            Self::Testnet => 0x6f,
        }
    }

    pub fn p2sh_byte(self) -> u8 {
        match self {
            Self::Mainnet => 0x05,
            Self::Testnet => 0xc4,
        }
    }

    /// WIF version byte (`PRIVKEYBYTE`).
    pub fn wif_byte(self) -> u8 {
        match self {
            Self::Mainnet => 0x80,
            Self::Testnet => 0xef,
        }
    }

    /// Default address-pool size: `--keypool` 100 on mainnet, hard-coded 10 on testnet.
    pub fn default_pool_size(self) -> usize {
        match self {
            Self::Mainnet => 100,
            Self::Testnet => 10,
        }
    }

    /// Base58Check P2PKH address for a hash160.
    pub fn p2pkh_address(self, hash160: &[u8; 20]) -> String {
        let mut payload = vec![self.p2pkh_byte()];
        payload.extend_from_slice(hash160);
        armory_crypto::base58::encode_check(&payload)
    }

    /// Uncompressed WIF (Armory never appends the compressed-key `01` suffix).
    pub fn wif(self, priv32: &[u8; 32]) -> String {
        let mut payload = vec![self.wif_byte()];
        payload.extend_from_slice(priv32);
        armory_crypto::base58::encode_check(&payload)
    }
}
