//! Armory's **non-standard** HMAC (`ArmoryUtils.py:1823-1835`).
//!
//! The key is hashed/padded to the *digest* size (32 for SHA-256, 64 for SHA-512) instead of
//! the hash *block* size that RFC 2104 uses, so the results differ from HMAC-SHA256/512 for
//! every key. Used for chain-code derivation, Shamir coefficients and SecurePrint codes.

use crate::hash::{sha256, sha512};

fn armory_hmac<const N: usize>(hash: fn(&[u8]) -> [u8; N], key: &[u8], msg: &[u8]) -> [u8; N] {
    let mut k = [0u8; N];
    if key.len() > N {
        k.copy_from_slice(&hash(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(N + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let inner_hash = hash(&inner);
    let mut outer = Vec::with_capacity(2 * N);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    hash(&outer)
}

/// `HMAC256(key, msg)` with Armory's 32-byte block.
pub fn hmac256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    armory_hmac(sha256, key, msg)
}

/// `HMAC512(key, msg)` with Armory's 64-byte block.
pub fn hmac512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    armory_hmac(sha512, key, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differs_from_rfc2104() {
        use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256 as bsha};
        let key = [0x0bu8; 20];
        let mut eng = HmacEngine::<bsha::Hash>::new(&key);
        eng.input(b"Hi There");
        let rfc = Hmac::<bsha::Hash>::from_engine(eng).to_byte_array();
        assert_ne!(hmac256(&key, b"Hi There"), rfc);
    }
}
