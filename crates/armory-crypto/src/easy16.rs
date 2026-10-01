//! Easy16 encoding and paper-backup lines (`ArmoryUtils.py:2161-2204`, spec 02 §1).
//!
//! Each hex digit `0123456789abcdef` maps to `asdfghjkwertuion`. A paper line holds 16 data
//! bytes plus a 2-byte checksum, printed as nine 4-character groups.

use crate::checksum::{Outcome, compute_checksum, verify_checksum};
use crate::{Error, Result};

const ALPHABET: &[u8; 16] = b"asdfghjkwertuion";

/// `binary_to_easyType16`.
pub fn encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(ALPHABET[(b >> 4) as usize] as char);
        s.push(ALPHABET[(b & 0x0f) as usize] as char);
    }
    s
}

/// `easyType16_to_binary`: unknown characters decode to nibble 0, as in Armory, so the
/// checksum can still repair a mistyped character.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let nibbles: Vec<u8> =
        s.chars().map(|c| ALPHABET.iter().position(|&a| a as char == c).unwrap_or(0) as u8).collect();
    if nibbles.len() % 2 != 0 {
        return Err(Error::InvalidLength { expected: nibbles.len() + 1, got: nibbles.len() });
    }
    Ok(nibbles.chunks(2).map(|p| (p[0] << 4) | p[1]).collect())
}

/// `makeSixteenBytesEasy`: `"QQQQ QQQQ QQQQ QQQQ  QQQQ QQQQ QQQQ QQQQ  CCCC"`.
pub fn make_line(data16: &[u8]) -> Result<String> {
    if data16.len() != 16 {
        return Err(Error::InvalidLength { expected: 16, got: data16.len() });
    }
    let mut b = data16.to_vec();
    b.extend(compute_checksum(data16, 2));
    let et = encode(&b);
    let quads: Vec<&str> = (0..9).map(|i| &et[i * 4..(i + 1) * 4]).collect();
    Ok(format!("{}  {}  {}", quads[..4].join(" "), quads[4..8].join(" "), quads[8]))
}

/// Result of reading one paper-backup line (`readSixteenEasyBytes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineStatus {
    /// Accepted as typed (this includes "data fine, a checksum character is wrong").
    Ok,
    /// Data was changed to satisfy the checksum (Armory's `Fixed_1`).
    Fixed,
}

/// `readSixteenEasyBytes`. Spaces are ignored; an uncorrectable line is an error
/// (Armory's `Error_2+`).
pub fn read_line(line: &str) -> Result<([u8; 16], LineStatus)> {
    let compact: String = line.trim().chars().filter(|c| *c != ' ').collect();
    let b18 = decode(&compact)?;
    if b18.len() != 18 {
        return Err(Error::InvalidLength { expected: 18, got: b18.len() });
    }
    let (data, chk) = b18.split_at(16);
    let v = verify_checksum(data, chk, true).ok_or(Error::Uncorrectable)?;
    if v.data.is_empty() || v.outcome == Outcome::EmptyField {
        return Err(Error::Uncorrectable);
    }
    let status = if v.data == data { LineStatus::Ok } else { LineStatus::Fixed };
    let mut out = [0u8; 16];
    out.copy_from_slice(&v.data);
    Ok((out, status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet() {
        assert_eq!(encode(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]), "asdfghjkwertuion");
    }

    // spec 02 §1.2 (computed from plain SHA-256)
    #[test]
    fn line_vectors() {
        assert_eq!(make_line(&[0u8; 16]).unwrap(), "aaaa aaaa aaaa aaaa  aaaa aaaa aaaa aaaa  wsnu");
        assert_eq!(make_line(&[0xaa; 16]).unwrap(), "rrrr rrrr rrrr rrrr  rrrr rrrr rrrr rrrr  sksi");
    }

    #[test]
    fn repairs_single_typo() {
        let data: [u8; 16] = core::array::from_fn(|i| i as u8 * 17);
        let line = make_line(&data).unwrap();
        let typo = line.replacen('a', "s", 1);
        let (got, status) = read_line(&typo).unwrap();
        assert_eq!(got, data);
        assert_eq!(status, LineStatus::Fixed);
        assert_eq!(read_line(&line).unwrap(), (data, LineStatus::Ok));
    }

    proptest::proptest! {
        #[test]
        fn roundtrip(data in proptest::array::uniform16(0u8..)) {
            let line = make_line(&data).unwrap();
            proptest::prop_assert_eq!(read_line(&line).unwrap(), (data, LineStatus::Ok));
        }
    }
}
