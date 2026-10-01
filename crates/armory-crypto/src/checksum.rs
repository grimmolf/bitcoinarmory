//! Checksums with Armory's single-byte error correction
//! (`computeChecksum`, `verifyChecksum`, `fixChecksumError`; `ArmoryUtils.py:2303-2377`).
//!
//! The search order matters: paper-backup restores must make exactly the same correction
//! decisions as Armory (spec 02 §2), so this is a literal port.

use crate::hash::hash256;

/// First 4 bytes of `hash256(b"")`: the checksum Armory writes for an empty field.
pub const EMPTY_CHECKSUM: [u8; 4] = [0x5d, 0xf6, 0xe0, 0xe2];

/// `hash256(data)[..n]`.
pub fn compute_checksum(data: &[u8], n: usize) -> Vec<u8> {
    hash256(data)[..n].to_vec()
}

/// How a value was accepted by [`verify_checksum`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The data matched its checksum unchanged.
    Valid,
    /// The byte-reversed data matched (Armory accepts "reversed endianness").
    Reversed,
    /// One data byte was replaced to make the checksum match.
    FixedByte,
    /// The data could not be fixed but the checksum is the empty-field checksum, so the field
    /// is treated as originally empty (the returned data is empty).
    EmptyField,
    /// The data is assumed correct because the checksum differs from it in one byte.
    ChecksumCorrupt,
}

/// The accepted data plus how it was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub data: Vec<u8>,
    pub outcome: Outcome,
}

impl Verified {
    /// True when the returned data differs from the input (Armory's `Fixed_1` condition).
    pub fn changed(&self, original: &[u8]) -> bool {
        self.data != original
    }
}

/// `fixChecksumError`: try every single-byte substitution, position ascending, value ascending;
/// the first match wins.
pub fn fix_checksum_error(data: &[u8], chk: &[u8]) -> Option<Vec<u8>> {
    let mut candidate = data.to_vec();
    for i in 0..data.len() {
        for v in 0..=255u8 {
            candidate[i] = v;
            if hash256(&candidate).starts_with(chk) {
                return Some(candidate);
            }
        }
        candidate[i] = data[i];
    }
    None
}

/// `verifyChecksum(data, chk, fixIfNecessary)`. `None` means unrecoverable (Python returns `''`).
pub fn verify_checksum(data: &[u8], chk: &[u8], fix_if_necessary: bool) -> Option<Verified> {
    let h = hash256(data);
    if h.starts_with(chk) {
        return Some(Verified { data: data.to_vec(), outcome: Outcome::Valid });
    }
    let reversed: Vec<u8> = data.iter().rev().copied().collect();
    if hash256(&reversed).starts_with(chk) {
        if fix_if_necessary {
            return Some(Verified { data: reversed, outcome: Outcome::Reversed });
        }
    } else if fix_if_necessary {
        if let Some(fixed) = fix_checksum_error(data, chk) {
            return Some(Verified { data: fixed, outcome: Outcome::FixedByte });
        }
        if chk == EMPTY_CHECKSUM {
            return Some(Verified { data: Vec::new(), outcome: Outcome::EmptyField });
        }
    }
    // A single corrupted checksum byte: the data is assumed correct.
    let mut c = chk.to_vec();
    for i in 0..chk.len() {
        for v in 0..=255u8 {
            c[i] = v;
            if h.starts_with(&c) {
                return Some(Verified { data: data.to_vec(), outcome: Outcome::ChecksumCorrupt });
            }
        }
        c[i] = chk[i];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // pytest/testArmoryEngineUtils.py:112-122
    #[test]
    fn legacy_vectors() {
        let mut data = vec![0x11u8];
        data.extend([0xaa; 31]);
        let chk = compute_checksum(&data, 4);

        assert_eq!(verify_checksum(&data, &chk, true).unwrap().data, data);

        let reversed: Vec<u8> = data.iter().rev().copied().collect();
        let r = verify_checksum(&reversed, &chk, true).unwrap();
        assert_eq!(r.data, data);

        let mut one_err = data.clone();
        one_err[31] = 0xab;
        assert_eq!(verify_checksum(&one_err, &chk, true).unwrap().data, data);
        assert!(verify_checksum(&one_err, &chk, false).is_none());

        let mut two_err = data.clone();
        two_err[30] = 0xab;
        two_err[31] = 0xab;
        assert!(verify_checksum(&two_err, &chk, true).is_none());
        assert!(verify_checksum(&two_err, &chk, false).is_none());
    }

    #[test]
    fn empty_field() {
        let v = verify_checksum(b"", &EMPTY_CHECKSUM, true).unwrap();
        assert!(v.data.is_empty());
        assert_eq!(v.outcome, Outcome::Valid);
    }

    #[test]
    fn corrupt_checksum_byte_keeps_data() {
        let data = [7u8; 16];
        let mut chk = compute_checksum(&data, 4);
        chk[2] ^= 0x40;
        let v = verify_checksum(&data, &chk, true).unwrap();
        assert_eq!(v.data, data);
    }
}
