//! The 237-byte `PyBtcAddress` record (spec 01 §3, `PyBtcAddress.py:871-1103`).

use armory_crypto::checksum::{EMPTY_CHECKSUM, compute_checksum, verify_checksum};
use armory_crypto::hash::hash160;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const RECORD_LEN: usize = 237;
/// `getVersionInt((1,35,0,0))`; always written as the record version.
pub const VERSION_1_35: u32 = 13_500_000;

pub const CHAIN_INDEX_ROOT: i64 = -1;
pub const CHAIN_INDEX_IMPORTED: i64 = -2;

/// Address flags (u64, LSB-first bitset).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AddrFlags {
    /// bit 0: a private key (plain, encrypted or pending) is present.
    pub has_priv: bool,
    /// bit 1: a public key is present.
    pub has_pub: bool,
    /// bit 2: the private-key slot holds AES-CFB ciphertext.
    pub encrypted: bool,
    /// bit 3: created while locked; the IV/priv slots hold an ancestor's pair.
    pub pending: bool,
}

impl AddrFlags {
    pub fn to_u64(self) -> u64 {
        u64::from(self.has_priv)
            | u64::from(self.has_pub) << 1
            | u64::from(self.encrypted) << 2
            | u64::from(self.pending) << 3
    }

    pub fn from_u64(v: u64) -> Self {
        Self { has_priv: v & 1 != 0, has_pub: v & 2 != 0, encrypted: v & 4 != 0, pending: v & 8 != 0 }
    }
}

/// One address entry. Fields are *logical* values: an empty `Vec` is an empty field.
#[derive(Clone, PartialEq, Eq)]
pub struct AddressRecord {
    pub addr160: [u8; 20],
    pub flags: AddrFlags,
    /// 32 bytes, or empty. Root: the wallet chain code; imported: `ff` x 32.
    pub chaincode: Vec<u8>,
    pub chain_index: i64,
    /// `createPrivKeyNextUnlock_ChainDepth`; meaningful only for pending records.
    pub chain_depth: i64,
    /// 16 bytes or empty.
    pub iv: Vec<u8>,
    /// Plaintext or ciphertext private key (32 bytes) or empty.
    pub priv_slot: Zeroizing<Vec<u8>>,
    /// 65-byte uncompressed public key or empty.
    pub pubkey: Vec<u8>,
    pub first_time: u64,
    pub last_time: u64,
    pub first_block: u32,
    pub last_block: u32,
}

impl std::fmt::Debug for AddressRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressRecord")
            .field("addr160", &self.addr160)
            .field("flags", &self.flags)
            .field("chain_index", &self.chain_index)
            .field("chain_depth", &self.chain_depth)
            .field("priv_slot", &if self.priv_slot.is_empty() { "<empty>" } else { "<redacted>" })
            .finish_non_exhaustive()
    }
}

fn chkzero(field: &[u8]) -> &[u8] {
    if field.iter().all(|b| *b == 0) { &[] } else { field }
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// `verify_checksum` that maps "unrecoverable" to `None` and keeps the empty-field semantics.
fn checked(field: &[u8], chk: &[u8]) -> Option<Vec<u8>> {
    verify_checksum(field, chk, true).map(|v| v.data)
}

fn put_field(out: &mut Vec<u8>, value: &[u8], width: usize) {
    let mut f = value.to_vec();
    f.resize(width, 0);
    out.extend_from_slice(&f);
    if value.is_empty() {
        out.extend_from_slice(&EMPTY_CHECKSUM);
    } else {
        out.extend_from_slice(&compute_checksum(value, 4));
    }
}

impl AddressRecord {
    /// `PyBtcAddress.unserialize`. `offset` is only used in error messages.
    pub fn parse(rec: &[u8], offset: usize) -> Result<Self> {
        if rec.len() < RECORD_LEN {
            return Err(Error::Truncated("address record"));
        }
        let corrupt = |what| Error::CorruptRecord { offset, what };
        let addr_raw = checked(&rec[0..20], &rec[20..24]).unwrap_or_default();
        let flags = AddrFlags::from_u64(u64_at(rec, 28));
        let addr_chk_error = addr_raw.len() != 20;
        if addr_chk_error && !flags.has_priv && !flags.has_pub {
            return Err(corrupt("address hash checksum"));
        }
        let chaincode = checked(chkzero(&rec[36..68]), &rec[68..72]).ok_or(corrupt("chaincode checksum"))?;
        let chain_index = u64_at(rec, 72) as i64;
        let chain_depth = u64_at(rec, 80) as i64;
        let iv = checked(chkzero(&rec[88..104]), &rec[104..108]);
        let priv_slot = checked(chkzero(&rec[108..140]), &rec[140..144]).map(Zeroizing::new);

        let (iv, priv_slot) = if flags.has_priv {
            let p = priv_slot.filter(|p| !p.is_empty()).ok_or(corrupt("private key checksum"))?;
            let iv = iv.unwrap_or_default();
            if flags.encrypted && iv.is_empty() {
                return Err(corrupt("IV checksum"));
            }
            (iv, p)
        } else {
            // Without bit 0 Armory discards the IV and private-key slots.
            (Vec::new(), Zeroizing::new(Vec::new()))
        };

        let mut pubkey = checked(chkzero(&rec[144..209]), &rec[209..213]).unwrap_or_default();
        if flags.has_pub && pubkey.len() != 65 {
            // Armory intended to recompute it from a plaintext key (the call is broken there).
            if !flags.encrypted && priv_slot.len() == 32 {
                pubkey = armory_crypto::chain::public_key(priv_slot[..].try_into().unwrap())?.to_vec();
            } else {
                return Err(corrupt("public key checksum"));
            }
        }
        let addr160: [u8; 20] = if addr_chk_error { hash160(&pubkey) } else { addr_raw.try_into().unwrap() };
        Ok(Self {
            addr160,
            flags,
            chaincode,
            chain_index,
            chain_depth,
            iv,
            priv_slot,
            pubkey,
            first_time: u64_at(rec, 213),
            last_time: u64_at(rec, 221),
            first_block: u32_at(rec, 229),
            last_block: u32_at(rec, 233),
        })
    }

    /// `PyBtcAddress.serialize`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECORD_LEN);
        out.extend_from_slice(&self.addr160);
        out.extend_from_slice(&compute_checksum(&self.addr160, 4));
        out.extend_from_slice(&VERSION_1_35.to_le_bytes());
        out.extend_from_slice(&self.flags.to_u64().to_le_bytes());
        put_field(&mut out, &self.chaincode, 32);
        out.extend_from_slice(&self.chain_index.to_le_bytes());
        out.extend_from_slice(&self.chain_depth.to_le_bytes());
        put_field(&mut out, &self.iv, 16);
        put_field(&mut out, &self.priv_slot, 32);
        put_field(&mut out, &self.pubkey, 65);
        out.extend_from_slice(&self.first_time.to_le_bytes());
        out.extend_from_slice(&self.last_time.to_le_bytes());
        out.extend_from_slice(&self.first_block.to_le_bytes());
        out.extend_from_slice(&self.last_block.to_le_bytes());
        debug_assert_eq!(out.len(), RECORD_LEN);
        out
    }

    /// A fresh record with Armory's initial "never seen" time/block ranges.
    pub fn new(addr160: [u8; 20], chain_index: i64) -> Self {
        Self {
            addr160,
            flags: AddrFlags::default(),
            chaincode: Vec::new(),
            chain_index,
            chain_depth: -1,
            iv: Vec::new(),
            priv_slot: Zeroizing::new(Vec::new()),
            pubkey: Vec::new(),
            first_time: u64::from(u32::MAX),
            last_time: 0,
            first_block: u32::MAX,
            last_block: 0,
        }
    }

    pub fn pubkey65(&self) -> Option<[u8; 65]> {
        self.pubkey.as_slice().try_into().ok()
    }

    pub fn is_imported(&self) -> bool {
        self.chain_index == CHAIN_INDEX_IMPORTED
    }

    /// Plaintext private key, if stored unencrypted.
    pub fn plain_priv(&self) -> Option<Zeroizing<[u8; 32]>> {
        if self.flags.has_priv && !self.flags.encrypted && self.priv_slot.len() == 32 {
            Some(Zeroizing::new(self.priv_slot[..].try_into().unwrap()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// spec 01 §14.3: unencrypted root record for priv aa x32, chain ee x32, IV 77 x16.
    #[test]
    fn root_record_vector() {
        let want = concat!(
            "5da74ed60a43a7ff11f0ba56cb0192b03518cc56",
            "2a446496",
            "60fecd00",
            "0300000000000000",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "c93a79dd",
            "ffffffffffffffff",
            "ffffffffffffffff",
            "77777777777777777777777777777777",
            "10b7b8f7",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "6dc8daeb",
        );
        let pub0 = armory_crypto::chain::public_key(&[0xaa; 32]).unwrap();
        let mut r = AddressRecord::new(hash160(&pub0), CHAIN_INDEX_ROOT);
        r.flags = AddrFlags { has_priv: true, has_pub: true, ..Default::default() };
        r.chaincode = vec![0xee; 32];
        r.iv = vec![0x77; 16];
        r.priv_slot = Zeroizing::new(vec![0xaa; 32]);
        r.pubkey = pub0.to_vec();
        let bytes = r.serialize();
        assert_eq!(hex::encode(&bytes[..144]), want);
        assert_eq!(hex::encode(&bytes[209..213]), "e475cb99");
        assert_eq!(hex::encode(&bytes[213..]), "ffffffff000000000000000000000000ffffffff00000000");
        assert_eq!(AddressRecord::parse(&bytes, 0).unwrap(), r);
    }

    #[test]
    fn repairs_single_byte_error() {
        let pub0 = armory_crypto::chain::public_key(&[0xaa; 32]).unwrap();
        let mut r = AddressRecord::new(hash160(&pub0), 0);
        r.flags = AddrFlags { has_priv: true, has_pub: true, ..Default::default() };
        r.chaincode = vec![0xee; 32];
        r.priv_slot = Zeroizing::new(vec![0xaa; 32]);
        r.pubkey = pub0.to_vec();
        let mut bytes = r.serialize();
        bytes[120] ^= 0x01; // inside the private key
        bytes[50] ^= 0x80; // inside the chain code
        assert_eq!(AddressRecord::parse(&bytes, 0).unwrap(), r);
    }
}
