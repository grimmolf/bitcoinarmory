//! `KdfRomix`: Armory's memory-hard key-derivation function
//! (`cppForSwig/EncryptionUtils.cpp:92-290`, spec 01 §5).
//!
//! A ROMix-style construction over SHA-512 with a lookup table of `mem` bytes, applied
//! `iterations` times; each later iteration takes the previous 32-byte output as password.

use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::hash::sha512;
use crate::{Error, Result};

const HSZ: usize = 64;

/// Parameters stored in the wallet header's 256-byte KDF block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_bytes: u32,
    pub iterations: u32,
    pub salt: [u8; 32],
}

impl KdfParams {
    pub fn validate(&self) -> Result<()> {
        let mem = self.memory_bytes as usize;
        if mem < 2 * HSZ || mem % HSZ != 0 {
            return Err(Error::KdfParams("memory must be a multiple of 64 and at least 128"));
        }
        Ok(())
    }

    /// `KdfRomix::DeriveKey`. With `iterations == 0` Armory returns the passphrase unchanged;
    /// that quirk is reproduced (it never occurs in calibrated wallets).
    pub fn derive_key(&self, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let mut key = Zeroizing::new(passphrase.to_vec());
        for _ in 0..self.iterations {
            let next = one_iteration(&key, &self.salt, self.memory_bytes as usize);
            key = Zeroizing::new(next.to_vec());
        }
        Ok(key)
    }

    /// `computeKdfParams`: calibrate memory and iterations so one derivation takes about
    /// `target` on this machine, capped at `max_memory` bytes. Uses a fresh random salt.
    pub fn calibrate(target: Duration, max_memory: u32) -> Self {
        use rand::RngCore;
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let target_s = target.as_secs_f64();
        if target_s == 0.0 {
            return Self { memory_bytes: 1024, iterations: 1, salt };
        }
        let mut test_key = b"This is an example key to test KDF iteration speed".to_vec();
        let mut mem: u32 = 1024;
        let mut elapsed = 0.0;
        while elapsed <= target_s / 4.0 && mem < max_memory {
            mem *= 2;
            let start = Instant::now();
            test_key = one_iteration(&test_key, &salt, mem as usize).to_vec();
            elapsed = start.elapsed().as_secs_f64();
        }
        let base = b"This is an example key to test KDF iteration speed";
        let mut num_test = 1u32;
        let mut all = 0.0;
        while all < 0.02 {
            num_test *= 2;
            let start = Instant::now();
            for _ in 0..num_test {
                one_iteration(base, &salt, mem as usize);
            }
            all = start.elapsed().as_secs_f64();
        }
        let per = all / f64::from(num_test) + 0.0005;
        let iterations = ((target_s / per).floor() as u32).max(1);
        Self { memory_bytes: mem, iterations, salt }
    }
}

/// `KdfRomix::DeriveKey_OneIter`.
fn one_iteration(password: &[u8], salt: &[u8], mem: usize) -> [u8; 32] {
    let seq = mem / HSZ;
    let mut lut = Zeroizing::new(vec![0u8; mem]);
    let mut seed = Vec::with_capacity(password.len() + salt.len());
    seed.extend_from_slice(password);
    seed.extend_from_slice(salt);
    lut[..HSZ].copy_from_slice(&sha512(&seed));
    seed.zeroize();
    for i in 0..seq - 1 {
        let next = sha512(&lut[i * HSZ..(i + 1) * HSZ]);
        lut[(i + 1) * HSZ..(i + 2) * HSZ].copy_from_slice(&next);
    }
    let mut x = [0u8; HSZ];
    x.copy_from_slice(&lut[mem - HSZ..]);
    let mut xv = [0u8; HSZ];
    for _ in 0..seq / 2 {
        // `*(uint32_t*)(X + HSZ - 4)` read natively: little-endian on every supported target.
        let idx = u32::from_le_bytes([x[60], x[61], x[62], x[63]]) as usize % seq;
        let v = &lut[idx * HSZ..(idx + 1) * HSZ];
        for j in 0..HSZ {
            xv[j] = x[j] ^ v[j];
        }
        x = sha512(&xv);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&x[..32]);
    x.zeroize();
    xv.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(mem: u32, iterations: u32, salt_hex: &str) -> KdfParams {
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&hex::decode(salt_hex).unwrap());
        KdfParams { memory_bytes: mem, iterations, salt }
    }

    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const GDHF_SALT: &str = "1ee82e6ef29655e597da9954b64aab87b470126c7b28b76d3d41168946305ffe";

    // tools/legacy-oracle/expected-output.txt (original EncryptionUtils.cpp + Crypto++)
    #[test]
    fn oracle_vectors() {
        let cases = [
            (
                b"abcde".as_slice(),
                1024,
                1,
                ZERO,
                "bc1f2cd96b766e91a7e2340f9564073f232d874778bce25c565ad26ea0ff3b6d",
            ),
            (b"abcde", 1024, 3, ZERO, "ddf620a364263c50c2abdbc85c230b586f52881268c24bd2ffe58d96080b3db8"),
            (
                b"This is my first password",
                65536,
                2,
                GDHF_SALT,
                "55562b96f019d234ea7bef95b1c8a096010eff56bb5bbf3c6332e5c6963ccb2a",
            ),
            (
                b"abcde",
                2097152,
                2,
                GDHF_SALT,
                "21d6716fcaebe82fd1f1a6ef43f244b759c5a888301cd1dae1685b6dbf1b847a",
            ),
            (b"abcde", 1024, 0, ZERO, "6162636465"),
        ];
        for (pw, mem, it, salt, want) in cases {
            let got = params(mem, it, salt).derive_key(pw).unwrap();
            assert_eq!(hex::encode(&*got), want, "mem={mem} iter={it}");
        }
    }

    #[test]
    fn rejects_bad_memory() {
        assert!(params(1000, 1, ZERO).derive_key(b"x").is_err());
    }
}
