//! Private keys typed or pasted by users (`parsePrivateKeyData`, `decodeMiniPrivateKey`;
//! `ArmoryUtils.py:2802-2884`, spec 01 §11).
//!
//! Accepted: WIF (uncompressed), 64-char hex, 72-char hex with a 4-byte checksum, and Casascius
//! mini keys (22, 26 or 30 characters). Compressed WIF keys are rejected for v1.35 wallets, which
//! store uncompressed public keys only (the address would differ); see issues #168/#190.

use armory_crypto::checksum::verify_checksum;
use armory_crypto::hash::{hash256, sha256};
use zeroize::Zeroizing;

use crate::network::LegacyNetwork;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyTextError {
    #[error("unrecognised private key format")]
    Unrecognised,
    #[error("private key checksum does not match")]
    BadChecksum,
    #[error("key is for a different network")]
    WrongNetwork,
    #[error(
        "compressed-key WIF cannot be stored in a v1.35 wallet (it would change the address); sweep it instead"
    )]
    Compressed,
    #[error("invalid mini private key")]
    BadMiniKey,
}

/// Decode a Casascius mini key: `sha256(s + "?")[0] == 0`, key = `sha256(s)`.
pub fn decode_mini_key(s: &str) -> Result<Zeroizing<[u8; 32]>, KeyTextError> {
    if ![22, 26, 30].contains(&s.len()) || !s.starts_with('S') {
        return Err(KeyTextError::BadMiniKey);
    }
    let check = sha256(format!("{s}?").as_bytes());
    if check[0] != 0 {
        return Err(KeyTextError::BadMiniKey);
    }
    Ok(Zeroizing::new(sha256(s.as_bytes())))
}

/// Parse a private key for `network`.
pub fn parse_private_key(text: &str, network: LegacyNetwork) -> Result<Zeroizing<[u8; 32]>, KeyTextError> {
    let s = text.trim();
    let is_hex = !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex && (s.len() == 64 || s.len() == 72) {
        let b = Zeroizing::new(
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
                .collect::<Vec<u8>>(),
        );
        if b.len() == 32 {
            return Ok(Zeroizing::new(b[..].try_into().unwrap()));
        }
        let v = verify_checksum(&b[..32], &b[32..], true).ok_or(KeyTextError::BadChecksum)?;
        return Ok(Zeroizing::new(v.data[..].try_into().map_err(|_| KeyTextError::BadChecksum)?));
    }
    if s.starts_with('S') && [22, 26, 30].contains(&s.len()) {
        return decode_mini_key(s);
    }
    let raw = Zeroizing::new(armory_crypto::base58::decode(s).map_err(|_| KeyTextError::Unrecognised)?);
    match raw.len() {
        37 | 38 => {
            let (body, chk) = raw.split_at(raw.len() - 4);
            if hash256(body)[..4] != *chk {
                return Err(KeyTextError::BadChecksum);
            }
            if body[0] != network.wif_byte() {
                return Err(KeyTextError::WrongNetwork);
            }
            if body.len() == 34 {
                return Err(KeyTextError::Compressed);
            }
            Ok(Zeroizing::new(body[1..33].try_into().unwrap()))
        }
        _ => Err(KeyTextError::Unrecognised),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // pytest/testArmoryEngineUtils.py:149-151
    #[test]
    fn mini_key() {
        let k = decode_mini_key("S4b3N3oGqDqR5jNuxEvDwf").unwrap();
        assert_eq!(hex::encode(*k), "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        assert_eq!(*parse_private_key("S4b3N3oGqDqR5jNuxEvDwf", LegacyNetwork::Mainnet).unwrap(), *k);
    }

    #[test]
    fn wif_and_hex() {
        let net = LegacyNetwork::Testnet;
        let k = [0x11u8; 32];
        let wif = net.wif(&k);
        assert_eq!(*parse_private_key(&wif, net).unwrap(), k);
        assert_eq!(parse_private_key(&wif, LegacyNetwork::Mainnet), Err(KeyTextError::WrongNetwork));
        assert_eq!(*parse_private_key(&hex::encode(k), net).unwrap(), k);
        let mut compressed = vec![net.wif_byte()];
        compressed.extend_from_slice(&k);
        compressed.push(1);
        let c = armory_crypto::base58::encode_check(&compressed);
        assert_eq!(parse_private_key(&c, net), Err(KeyTextError::Compressed));
    }
}
