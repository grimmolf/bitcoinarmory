//! Raw base58 without an implicit checksum (`binary_to_base58`, `ArmoryUtils.py:1997-2059`).
//! Armory appends checksums itself where it wants them; wallet IDs and SecurePrint codes have
//! none.

use crate::{Error, Result};

pub fn encode(data: &[u8]) -> String {
    bitcoin::base58::encode(data)
}

pub fn decode(s: &str) -> Result<Vec<u8>> {
    bitcoin::base58::decode(s).map_err(|_| {
        let bad = s
            .chars()
            .find(|c| !"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(*c))
            .unwrap_or('?');
        Error::InvalidCharacter(bad)
    })
}

/// `base58(data || hash256(data)[:4])`: addresses and WIF keys.
pub fn encode_check(data: &[u8]) -> String {
    bitcoin::base58::encode_check(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros() {
        assert_eq!(encode(&[0, 0, 1]), "112");
        assert_eq!(decode("112").unwrap(), vec![0, 0, 1]);
        assert_eq!(decode("0OIl"), Err(Error::InvalidCharacter('0')));
    }
}
