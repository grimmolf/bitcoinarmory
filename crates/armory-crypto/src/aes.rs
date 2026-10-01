//! AES-256 in the two modes Armory uses, without padding
//! (`CryptoAES::EncryptCFB/DecryptCFB/EncryptCBC/DecryptCBC`, `EncryptionUtils.cpp:298-420`).
//!
//! * CFB-128 encrypts wallet private keys (spec 01 §6.1).
//! * CBC masks SecurePrint paper backups (spec 02 §3.5); input must be a multiple of 16 bytes.

use aes::Aes256;
use aes::Block;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

use crate::{Error, Result};

fn cipher(key: &[u8]) -> Result<Aes256> {
    Aes256::new_from_slice(key).map_err(|_| Error::InvalidLength { expected: 32, got: key.len() })
}

fn check_iv(iv: &[u8]) -> Result<()> {
    if iv.len() != 16 {
        return Err(Error::InvalidLength { expected: 16, got: iv.len() });
    }
    Ok(())
}

fn cfb(key: &[u8], iv: &[u8], data: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    let c = cipher(key)?;
    check_iv(iv)?;
    let mut feedback = Block::clone_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = feedback;
        c.encrypt_block(&mut ks);
        let produced: Vec<u8> = chunk.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        let cipher_block = if decrypt { chunk } else { &produced[..] };
        if cipher_block.len() == 16 {
            feedback = Block::clone_from_slice(cipher_block);
        }
        out.extend_from_slice(&produced);
    }
    Ok(out)
}

pub fn encrypt_cfb(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    cfb(key, iv, plaintext, false)
}

pub fn decrypt_cfb(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    cfb(key, iv, ciphertext, true)
}

fn check_blocks(data: &[u8]) -> Result<()> {
    if data.len() % 16 != 0 {
        return Err(Error::InvalidLength { expected: data.len().next_multiple_of(16), got: data.len() });
    }
    Ok(())
}

pub fn encrypt_cbc(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let c = cipher(key)?;
    check_iv(iv)?;
    check_blocks(plaintext)?;
    let mut prev = Block::clone_from_slice(iv);
    let mut out = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks(16) {
        let mut block = Block::clone_from_slice(chunk);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        c.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        prev = block;
    }
    Ok(out)
}

pub fn decrypt_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let c = cipher(key)?;
    check_iv(iv)?;
    check_blocks(ciphertext)?;
    let mut prev = Block::clone_from_slice(iv);
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let mut block = Block::clone_from_slice(chunk);
        c.decrypt_block(&mut block);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        out.extend_from_slice(&block);
        prev = Block::clone_from_slice(chunk);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // pytest/testPyBtcAddress.py:22-23, confirmed by tools/legacy-oracle
    #[test]
    fn wallet_vectors() {
        let iv = h("77777777777777777777777777777777");
        let plain = [0xaau8; 32];
        let c1 = encrypt_cfb(&[0x11; 32], &iv, &plain).unwrap();
        assert_eq!(hex::encode(&c1), "500c41607d79c766859e6d9726ef1ea0fdf095922f3324454f6c4c34abcb23a5");
        let c2 = encrypt_cfb(&[0x22; 32], &iv, &plain).unwrap();
        assert_eq!(hex::encode(&c2), "7966cf5886494246cc5aaf7f1a4a2777cd6126612e7029d79ef9df47f6d6927d");
        assert_eq!(decrypt_cfb(&[0x11; 32], &iv, &c1).unwrap(), plain);
    }

    // cppForSwig/old_not_very_good_tests.cpp:1452-1492 (NIST AES-256 CFB, plaintext 16x00)
    #[test]
    fn nist_cfb() {
        let zero = [0u8; 16];
        let mut key3 = h("ffffffffffff");
        key3.resize(32, 0);
        let cases = [
            (vec![0u8; 32], h("80000000000000000000000000000000"), "ddc6bf790c15760d8d9aeb6f9a75fd4e"),
            (vec![0u8; 32], h("014730f80ac625fe84f026c60bfd547d"), "5c9d844ed46f9885085e5d6a4f94c7d7"),
            (key3, vec![0u8; 16], "225f068c28476605735ad671bb8f39f3"),
        ];
        for (key, iv, want) in cases {
            assert_eq!(hex::encode(encrypt_cfb(&key, &iv, &zero).unwrap()), want);
        }
    }

    #[test]
    fn cbc_roundtrip_and_known_answer() {
        // NIST SP 800-38A F.2.5 CBC-AES256.Encrypt, first block
        let key = h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv = h("000102030405060708090a0b0c0d0e0f");
        let pt = h("6bc1bee22e409f96e93d7e117393172a");
        let ct = encrypt_cbc(&key, &iv, &pt).unwrap();
        assert_eq!(hex::encode(&ct), "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
        assert_eq!(decrypt_cbc(&key, &iv, &ct).unwrap(), pt);
        assert!(encrypt_cbc(&key, &iv, &[0u8; 20]).is_err());
    }
}
