//! The legacy Armory 1.35 deterministic key chain (spec 01 §7). This is **not** BIP32.
//!
//! ```text
//! mult[i]   = chaincode XOR hash256(pub65[i])
//! priv[i+1] = mult[i] * priv[i]   (mod n)
//! pub[i+1]  = mult[i] * pub[i]
//! ```
//! Public keys are always hashed in their 65-byte uncompressed form.

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use num_bigint::BigUint;
use zeroize::Zeroizing;

use crate::hash::{hash160, hash256};
use crate::hmac::hmac256;
use crate::{Error, Result, base58};

/// Message used by `DeriveChaincodeFromRootKey` (`ArmoryUtils.py:3423-3425`).
const CHAINCODE_MSG: &[u8] = b"Derive Chaincode from Root Key";

/// secp256k1 group order.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba,
    0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The chain code of every wallet created by Armory ≥ 1.35a. Older wallets carry a random chain
/// code, so readers must always prefer the one stored in the file.
pub fn derive_chaincode(root_priv: &[u8; 32]) -> [u8; 32] {
    hmac256(&hash256(root_priv), CHAINCODE_MSG)
}

/// Uncompressed 65-byte public key `04 || X || Y`.
pub fn public_key(priv32: &[u8; 32]) -> Result<[u8; 65]> {
    let sk = SecretKey::from_slice(priv32).map_err(|_| Error::InvalidKey)?;
    Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), &sk).serialize_uncompressed())
}

/// `chaincode XOR hash256(pub65)` reduced mod n so it can be used as a scalar.
fn multiplier(pub65: &[u8; 65], chaincode: &[u8; 32]) -> Result<Scalar> {
    let h = hash256(pub65);
    let mut m = [0u8; 32];
    for i in 0..32 {
        m[i] = chaincode[i] ^ h[i];
    }
    let reduced = BigUint::from_bytes_be(&m) % BigUint::from_bytes_be(&ORDER);
    let bytes = reduced.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Scalar::from_be_bytes(out).map_err(|_| Error::InvalidKey)
}

/// The raw multiplier bytes (`chaincode XOR hash256(pub65)`), exposed for test vectors.
pub fn raw_multiplier(pub65: &[u8; 65], chaincode: &[u8; 32]) -> [u8; 32] {
    let h = hash256(pub65);
    core::array::from_fn(|i| chaincode[i] ^ h[i])
}

/// `CryptoECDSA::ComputeChainedPrivateKey` (`EncryptionUtils.cpp:719-791`).
pub fn chained_private_key(priv32: &[u8; 32], chaincode: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let pub65 = public_key(priv32)?;
    let sk = SecretKey::from_slice(priv32).map_err(|_| Error::InvalidKey)?;
    let next = sk.mul_tweak(&multiplier(&pub65, chaincode)?).map_err(|_| Error::InvalidKey)?;
    Ok(Zeroizing::new(next.secret_bytes()))
}

/// `CryptoECDSA::ComputeChainedPublicKey` (`EncryptionUtils.cpp:795-843`).
pub fn chained_public_key(pub65: &[u8; 65], chaincode: &[u8; 32]) -> Result<[u8; 65]> {
    let pk = PublicKey::from_slice(pub65).map_err(|_| Error::InvalidKey)?;
    let next = pk
        .mul_tweak(&Secp256k1::verification_only(), &multiplier(pub65, chaincode)?)
        .map_err(|_| Error::InvalidKey)?;
    Ok(next.serialize_uncompressed())
}

/// Six-byte wallet ID: `reverse(netbyte || hash160(pub65 of chain index 0)[..5])`.
pub fn wallet_id_bin(first_chained_pub65: &[u8; 65], p2pkh_byte: u8) -> [u8; 6] {
    let h = hash160(first_chained_pub65);
    [h[4], h[3], h[2], h[1], h[0], p2pkh_byte]
}

/// Base58 wallet ID shown to users (e.g. `GDHFnMQ2`); no checksum.
pub fn wallet_id(first_chained_pub65: &[u8; 65], p2pkh_byte: u8) -> String {
    base58::encode(&wallet_id_bin(first_chained_pub65, p2pkh_byte))
}

/// Wallet ID computed from root material, as a paper-backup restore does.
pub fn wallet_id_from_root(root_priv: &[u8; 32], chaincode: &[u8; 32], p2pkh_byte: u8) -> Result<String> {
    let root_pub = public_key(root_priv)?;
    let first = chained_public_key(&root_pub, chaincode)?;
    Ok(wallet_id(&first, p2pkh_byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    const PUB0: &str = "046a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb336b6fbcb60b5b3d4f1551ac45e5ffc4936466e7d98f6c7c0ec736539f74691a6";

    // tools/legacy-oracle/expected-output.txt and pytest/testPyBtcAddress.py:24-27
    #[test]
    fn oracle_chain() {
        let priv0 = [0xaau8; 32];
        let cc = [0xeeu8; 32];
        let pub0 = public_key(&priv0).unwrap();
        assert_eq!(hex::encode(pub0), PUB0);
        assert_eq!(hex::encode(hash160(&pub0)), "5da74ed60a43a7ff11f0ba56cb0192b03518cc56");
        assert_eq!(
            hex::encode(raw_multiplier(&pub0, &cc)),
            "0a9b2577729fc5b719275c036b8101a085396e4f95ed1e3a65b447bdfe00c8e3"
        );
        let priv1 = chained_private_key(&priv0, &cc).unwrap();
        assert_eq!(hex::encode(*priv1), "0db5c1e9a8d1ebc0525bdb534626033b948804a9a34871d67bf58a3df11d6888");
        let priv2 = chained_private_key(&priv1, &cc).unwrap();
        assert_eq!(hex::encode(*priv2), "5db1314a20ae9fc978477ab3fe16ab17b246d813a541ecdd4143fcf082b19407");

        let pub1 = chained_public_key(&pub0, &cc).unwrap();
        assert_eq!(hex::encode(hash160(&pub1)), "fb80e6fd042fa24178b897a6a70e1ae7eb56a20a");
        let pub2 = chained_public_key(&pub1, &cc).unwrap();
        assert_eq!(
            hex::encode(pub2),
            "046c35e36776e997883ad4269dcc0696b10d68f6864ae73b8ad6ad03e879e43062a0139095ece3bd653b809fa7e8c7d78ffe6fac75a84c8283d8a000890bfc879d"
        );
        assert_eq!(public_key(&priv2).unwrap(), pub2);
    }

    // pytest/testPyBtcWallet.py:32 (testnet) and spec 01 §14.3 (mainnet)
    #[test]
    fn wallet_ids() {
        let id_t = wallet_id_from_root(&[0xaa; 32], &[0xee; 32], 0x6f).unwrap();
        assert_eq!(id_t, "3VB8XSoY");
        let id_m = wallet_id_from_root(&[0xaa; 32], &[0xee; 32], 0x00).unwrap();
        assert_eq!(id_m, "3VB8XSmd");
    }

    // spec 01 §14.3 (Armory HMAC, confirmed on all three fixture wallets)
    #[test]
    fn chaincode_from_root() {
        assert_eq!(
            hex::encode(derive_chaincode(&[0xaa; 32])),
            "cd0784defd9a0fbc4ecc1b306eb7679b3a9c5a23f340b2453aadc482ed10c5dc"
        );
        let _ = arr::<32>("cd0784defd9a0fbc4ecc1b306eb7679b3a9c5a23f340b2453aadc482ed10c5dc");
    }
}
