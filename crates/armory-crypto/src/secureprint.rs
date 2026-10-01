//! SecurePrint: masking of paper backups with a short code shown only on screen
//! (`HardcodedKeyMaskParams`, `ArmoryUtils.py:3442-3503`, spec 02 §3).
//!
//! * code = base58(bin7 || hash256(bin7)[0]), bin7 = HMAC512(hash256(root || chain), SALT)[:7]
//! * key  = KdfRomix(16 MiB, 1 iteration, SALT) over the **ASCII text** of the code
//! * mask = AES-256-CBC(key, fixed IV), no padding, each 32-byte field masked independently

use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::hash::hash256;
use crate::hmac::hmac512;
use crate::kdf::KdfParams;
use crate::{Result, aes, base58};

const DIGITS_PI: &str = concat!(
    "ARMORY_ENCRYPTION_INITIALIZATION_VECTOR_",
    "1415926535897932384626433832795028841971693993751058209749445923",
    "0781640628620899862803482534211706798214808651328230664709384460",
    "9550582231725359408128481117450284102701938521105559644622948954",
    "9303819644288109756659334461284756482337867831652712019091456485",
);

const DIGITS_E: &str = concat!(
    "ARMORY_KEY_DERIVATION_FUNCTION_SALT_",
    "7182818284590452353602874713526624977572470936999595749669676277",
    "2407663035354759457138217852516642742746639193200305992181741359",
    "6629043572900334295260595630738132328627943490763233829880753195",
    "2510190115738341879307021540891499348841675092447614606680822648",
);

/// KDF memory: 16 MiB.
pub const KDF_BYTES: u32 = 16 * 1024 * 1024;

/// Fixed IV: `hash256(digits_pi)[:16]`.
pub fn iv() -> [u8; 16] {
    hash256(DIGITS_PI.as_bytes())[..16].try_into().unwrap()
}

/// Fixed salt: `hash256(digits_e)`.
pub fn salt() -> [u8; 32] {
    hash256(DIGITS_E.as_bytes())
}

fn kdf_params() -> &'static KdfParams {
    static P: OnceLock<KdfParams> = OnceLock::new();
    P.get_or_init(|| KdfParams { memory_bytes: KDF_BYTES, iterations: 1, salt: salt() })
}

/// The SecurePrint code for a wallet. Callers always pass `root_priv || chaincode` (64 bytes),
/// even for 1.35c wallets whose chain code is not printed.
pub fn create_code(secret: &[u8]) -> String {
    let h = hmac512(&hash256(secret), &salt());
    let mut bin8 = h[..7].to_vec();
    bin8.push(hash256(&bin8)[0]);
    base58::encode(&bin8)
}

/// `checkSecurePrintCode` (GUI rules): at least 9 characters, valid base58, and the trailing
/// byte equals `hash256(first 7 bytes)[0]`.
pub fn check_code(code: &str) -> bool {
    let code = code.trim();
    if code.len() < 9 {
        return false;
    }
    match base58::decode(code) {
        Ok(b) if b.len() >= 8 => hash256(&b[..7])[0] == b[b.len() - 1],
        _ => false,
    }
}

/// The 32-byte AES key derived from the code text (about 16 MiB of memory, under a second).
pub fn derive_key(code: &str) -> Result<Zeroizing<Vec<u8>>> {
    kdf_params().derive_key(code.trim().as_bytes())
}

pub fn mask(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    aes::encrypt_cbc(key, &iv(), data)
}

pub fn unmask(key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(aes::decrypt_cbc(key, &iv(), data)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::derive_chaincode;

    // spec 02 §3.1 (plain SHA-256 of the literals)
    #[test]
    fn constants() {
        assert_eq!(hex::encode(iv()), "b928d97f9c81ad16baeb12a19845068e");
        assert_eq!(hex::encode(salt()), "68287df541e90879dde18208b45fd80f59de7c969abc2adf580fc449c1b89652");
    }

    // spec 02 §9.6 vector A [port-generated; its primitives are verified against the original
    // C++ (KDF, AES) and the fixture wallets (Armory HMAC)]
    #[test]
    fn vector_a() {
        let root = [0xaau8; 32];
        let chain = derive_chaincode(&root);
        let mut secret = root.to_vec();
        secret.extend_from_slice(&chain);
        let code = create_code(&secret);
        assert_eq!(code, "8rDHqahJzK8");
        assert!(check_code(&code));
        assert!(!check_code("8rDHqahJzK9"));
        let key = derive_key(&code).unwrap();
        assert_eq!(hex::encode(&*key), "8e358a71ea851cffab60757bb4776d6bcac0fd8af4d54259d65cc0c31a94976c");
        let masked = mask(&key, &root).unwrap();
        let lines = [
            crate::easy16::make_line(&masked[..16]).unwrap(),
            crate::easy16::make_line(&masked[16..]).unwrap(),
        ];
        assert_eq!(lines[0], "neaj drei hwwo ffih  nkki sdij ajgi nhtf  hhnn");
        assert_eq!(lines[1], "dkhh hhad fisd gjre  ngts nwwe fgns wjhd  juwg");
        assert_eq!(*unmask(&key, &masked).unwrap(), root);
    }
}
