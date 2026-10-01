//! Hash functions as used by Armory (`ArmoryUtils.py:1805-1820`).

use bitcoin::hashes::{Hash, ripemd160, sha256, sha256d, sha512};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    sha512::Hash::hash(data).to_byte_array()
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    ripemd160::Hash::hash(data).to_byte_array()
}

/// `sha256(sha256(data))`, in digest byte order (not the reversed display order).
pub fn hash256(data: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(data).to_byte_array()
}

/// `ripemd160(sha256(data))`.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    // pytest/testArmoryEngineUtils.py:78-79,171-172
    #[test]
    fn legacy_vectors() {
        assert_eq!(hex::encode(ripemd160(&[0x0f, 0xfd])), "13988143ae67128f883765a4a4b19d77c1ea1ee9");
        assert_eq!(hex::encode(hash160(&[0x0f, 0xfd])), "d418dd224e11e1d3b37b5f46b072ccf4e4e26203");
        assert_eq!(
            hex::encode(hash256(b"")),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }
}
