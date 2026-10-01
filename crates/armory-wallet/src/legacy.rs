//! Legacy Armory `.wallet` file, format v1.35 (spec 01 §2, §4, §6-§8).
//!
//! [`LegacyWallet::parse`] followed by [`LegacyWallet::serialize`] reproduces a canonical file
//! byte for byte; the raw KDF, crypto and reserved blocks and every entry are kept in file order
//! so nothing is lost on rewrite.

use std::collections::BTreeMap;
use std::time::Duration;

use armory_crypto::checksum::{compute_checksum, verify_checksum};
use armory_crypto::hash::hash160;
use armory_crypto::kdf::KdfParams;
use armory_crypto::{aes, chain};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::network::LegacyNetwork;
use crate::record::{
    AddrFlags, AddressRecord, CHAIN_INDEX_IMPORTED, CHAIN_INDEX_ROOT, RECORD_LEN, VERSION_1_35,
};
use crate::{Error, Result};

pub const FILE_ID: [u8; 8] = *b"\xbaWALLET\x00";
pub const HEADER_LEN: usize = 2107;
const OFF_FLAGS: usize = 16;
const OFF_ID: usize = 24;
const OFF_CREATED: usize = 30;
const OFF_LABEL: usize = 38;
const OFF_DESCR: usize = 70;
const OFF_HIGHEST: usize = 326;
const OFF_KDF: usize = 334;
const OFF_CRYPTO: usize = 590;
const OFF_ROOT: usize = 846;
const OFF_RESERVED: usize = 1083;
pub const LABEL_LEN: usize = 32;
pub const DESCR_LEN: usize = 256;

const T_KEY: u8 = 0;
const T_ADDR_COMMENT: u8 = 1;
const T_TX_COMMENT: u8 = 2;
const T_OPEVAL: u8 = 3;
const T_DELETED: u8 = 4;

/// Header flags (u64 at offset 16, LSB-first).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalletFlags {
    pub encrypted: bool,
    pub watching_only: bool,
}

/// One item of the entry stream, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Key {
        hash: [u8; 20],
        record: AddressRecord,
    },
    AddrComment {
        hash: [u8; 20],
        comment: Vec<u8>,
    },
    /// `hash` is the internal (little-endian) transaction hash.
    TxComment {
        hash: [u8; 32],
        comment: Vec<u8>,
    },
    Deleted {
        data: Vec<u8>,
    },
    /// A byte with an unknown type code; Armory skips it one byte at a time.
    Unknown(u8),
}

impl Entry {
    fn serialize_into(&self, out: &mut Vec<u8>) {
        match self {
            Entry::Key { hash, record } => {
                out.push(T_KEY);
                out.extend_from_slice(hash);
                out.extend_from_slice(&record.serialize());
            }
            Entry::AddrComment { hash, comment } => {
                out.push(T_ADDR_COMMENT);
                out.extend_from_slice(hash);
                out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
                out.extend_from_slice(comment);
            }
            Entry::TxComment { hash, comment } => {
                out.push(T_TX_COMMENT);
                out.extend_from_slice(hash);
                out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
                out.extend_from_slice(comment);
            }
            Entry::Deleted { data } => {
                out.push(T_DELETED);
                out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                out.extend_from_slice(data);
            }
            Entry::Unknown(b) => out.push(*b),
        }
    }
}

/// A parsed v1.35 wallet.
#[derive(Debug, Clone)]
pub struct LegacyWallet {
    pub network: LegacyNetwork,
    pub version: u32,
    pub flags: WalletFlags,
    pub unique_id: [u8; 6],
    pub create_date: u64,
    label_raw: [u8; LABEL_LEN],
    descr_raw: [u8; DESCR_LEN],
    pub highest_used: i64,
    kdf_raw: [u8; 256],
    pub kdf: Option<KdfParams>,
    crypto_raw: [u8; 256],
    pub root: AddressRecord,
    reserved: Vec<u8>,
    pub entries: Vec<Entry>,
    /// True when parsing had to repair data (Armory would rewrite the file).
    pub repaired: bool,
}

fn strip_nuls(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| *c != 0).unwrap_or(b.len());
    let end = b.iter().rposition(|c| *c != 0).map_or(start, |e| e + 1);
    &b[start..end]
}

fn fixed<const N: usize>(b: &[u8]) -> [u8; N] {
    b[..N].try_into().unwrap()
}

fn kdf_block(p: &KdfParams) -> [u8; 256] {
    let mut b = [0u8; 256];
    b[0..8].copy_from_slice(&u64::from(p.memory_bytes).to_le_bytes());
    b[8..12].copy_from_slice(&p.iterations.to_le_bytes());
    b[12..44].copy_from_slice(&p.salt);
    let chk = compute_checksum(&b[0..44], 4);
    b[44..48].copy_from_slice(&chk);
    b
}

fn parse_kdf(raw: &[u8; 256]) -> Result<(Option<KdfParams>, Option<[u8; 44]>)> {
    if raw[0..44].iter().all(|b| *b == 0) {
        return Ok((None, None));
    }
    let v = verify_checksum(&raw[0..44], &raw[44..48], true)
        .filter(|v| v.data.len() == 44)
        .ok_or(Error::CorruptRecord { offset: OFF_KDF, what: "KDF parameter checksum" })?;
    let d = &v.data;
    let mem = u64::from_le_bytes(fixed(&d[0..8]));
    let params = KdfParams {
        memory_bytes: u32::try_from(mem)
            .map_err(|_| Error::CorruptRecord { offset: OFF_KDF, what: "KDF memory exceeds 4 GiB" })?,
        iterations: u32::from_le_bytes(fixed(&d[8..12])),
        salt: fixed(&d[12..44]),
    };
    let corrected = (d[..] != raw[0..44]).then(|| fixed::<44>(d));
    Ok((Some(params), corrected))
}

fn random_iv() -> Vec<u8> {
    let mut iv = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    iv
}

impl LegacyWallet {
    /// Parse a complete wallet file.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 || bytes[0..8] != FILE_ID {
            return Err(Error::NotAWallet);
        }
        if bytes.len() < HEADER_LEN {
            return Err(Error::Truncated("header"));
        }
        let version = u32::from_le_bytes(fixed(&bytes[8..12]));
        if version < VERSION_1_35 {
            return Err(Error::TooOld(version));
        }
        let magic: [u8; 4] = fixed(&bytes[12..16]);
        let network = LegacyNetwork::from_magic(magic).ok_or(Error::UnknownNetwork(magic))?;
        let flag_bits = u64::from_le_bytes(fixed(&bytes[OFF_FLAGS..OFF_FLAGS + 8]));
        if flag_bits & 4 != 0 {
            return Err(Error::MultisigWallet);
        }
        let flags = WalletFlags { encrypted: flag_bits & 1 != 0, watching_only: flag_bits & 2 != 0 };
        let unique_id: [u8; 6] = fixed(&bytes[OFF_ID..OFF_ID + 6]);
        if unique_id[5] != network.p2pkh_byte() {
            return Err(Error::NetworkMismatch { id: unique_id[5], header: network });
        }
        let kdf_raw: [u8; 256] = fixed(&bytes[OFF_KDF..OFF_KDF + 256]);
        let (kdf, kdf_fix) = parse_kdf(&kdf_raw)?;
        let mut repaired = kdf_fix.is_some();
        let mut kdf_raw = kdf_raw;
        if let Some(fix) = kdf_fix {
            kdf_raw[0..44].copy_from_slice(&fix);
        }
        let root_raw = &bytes[OFF_ROOT..OFF_ROOT + RECORD_LEN];
        let root = AddressRecord::parse(root_raw, OFF_ROOT)?;
        repaired |= root.serialize() != root_raw;

        let mut entries = Vec::new();
        let mut pos = HEADER_LEN;
        while pos < bytes.len() {
            let t = bytes[pos];
            let rest = &bytes[pos + 1..];
            let need = |n: usize| if rest.len() < n { Err(Error::Truncated("entry")) } else { Ok(()) };
            match t {
                T_KEY => {
                    need(20 + RECORD_LEN)?;
                    let raw = &rest[20..20 + RECORD_LEN];
                    let record = AddressRecord::parse(raw, pos + 21)?;
                    repaired |= record.serialize() != raw;
                    entries.push(Entry::Key { hash: fixed(&rest[..20]), record });
                    pos += 1 + 20 + RECORD_LEN;
                }
                T_ADDR_COMMENT | T_TX_COMMENT => {
                    let hl = if t == T_ADDR_COMMENT { 20 } else { 32 };
                    need(hl + 2)?;
                    let len = u16::from_le_bytes(fixed(&rest[hl..hl + 2])) as usize;
                    need(hl + 2 + len)?;
                    let comment = rest[hl + 2..hl + 2 + len].to_vec();
                    entries.push(if t == T_ADDR_COMMENT {
                        Entry::AddrComment { hash: fixed(&rest[..20]), comment }
                    } else {
                        Entry::TxComment { hash: fixed(&rest[..32]), comment }
                    });
                    pos += 1 + hl + 2 + len;
                }
                T_OPEVAL => return Err(Error::UnsupportedEntry(t)),
                T_DELETED => {
                    need(2)?;
                    let len = u16::from_le_bytes(fixed(&rest[..2])) as usize;
                    need(2 + len)?;
                    entries.push(Entry::Deleted { data: rest[2..2 + len].to_vec() });
                    pos += 3 + len;
                }
                other => {
                    entries.push(Entry::Unknown(other));
                    pos += 1;
                }
            }
        }

        Ok(Self {
            network,
            version,
            flags,
            unique_id,
            create_date: u64::from_le_bytes(fixed(&bytes[OFF_CREATED..OFF_CREATED + 8])),
            label_raw: fixed(&bytes[OFF_LABEL..OFF_LABEL + LABEL_LEN]),
            descr_raw: fixed(&bytes[OFF_DESCR..OFF_DESCR + DESCR_LEN]),
            highest_used: i64::from_le_bytes(fixed(&bytes[OFF_HIGHEST..OFF_HIGHEST + 8])),
            kdf_raw,
            kdf,
            crypto_raw: fixed(&bytes[OFF_CRYPTO..OFF_CRYPTO + 256]),
            root,
            reserved: bytes[OFF_RESERVED..HEADER_LEN].to_vec(),
            entries,
            repaired,
        })
    }

    /// The complete file contents.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.entries.len() * 258);
        out.extend_from_slice(&FILE_ID);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.network.magic());
        let flags = u64::from(self.flags.encrypted) | u64::from(self.flags.watching_only) << 1;
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&self.unique_id);
        out.extend_from_slice(&self.create_date.to_le_bytes());
        out.extend_from_slice(&self.label_raw);
        out.extend_from_slice(&self.descr_raw);
        out.extend_from_slice(&self.highest_used.to_le_bytes());
        out.extend_from_slice(&self.kdf_raw);
        out.extend_from_slice(&self.crypto_raw);
        out.extend_from_slice(&self.root.serialize());
        out.extend_from_slice(&self.reserved);
        debug_assert_eq!(out.len(), HEADER_LEN);
        for e in &self.entries {
            e.serialize_into(&mut out);
        }
        out
    }

    // ----------------------------------------------------------------- identity and labels

    /// Base58 wallet ID, e.g. `GDHFnMQ2`.
    pub fn id(&self) -> String {
        armory_crypto::base58::encode(&self.unique_id)
    }

    /// Default file name `armory_<ID>_.wallet`.
    pub fn default_file_name(&self) -> String {
        format!("armory_{}_.wallet", self.id())
    }

    pub fn label(&self) -> String {
        String::from_utf8_lossy(strip_nuls(&self.label_raw)).into_owned()
    }

    pub fn description(&self) -> String {
        String::from_utf8_lossy(strip_nuls(&self.descr_raw)).into_owned()
    }

    /// Set labels (UTF-8; Armory truncates to 32 and 256 bytes, this refuses instead).
    pub fn set_labels(&mut self, label: &str, description: &str) -> Result<()> {
        if label.len() > LABEL_LEN {
            return Err(Error::LabelTooLong(label.len(), LABEL_LEN));
        }
        if description.len() > DESCR_LEN {
            return Err(Error::LabelTooLong(description.len(), DESCR_LEN));
        }
        self.label_raw = [0; LABEL_LEN];
        self.label_raw[..label.len()].copy_from_slice(label.as_bytes());
        self.descr_raw = [0; DESCR_LEN];
        self.descr_raw[..description.len()].copy_from_slice(description.as_bytes());
        Ok(())
    }

    pub fn is_watching_only(&self) -> bool {
        self.flags.watching_only || !self.root.flags.has_priv
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags.encrypted
    }

    pub fn chaincode(&self) -> Result<[u8; 32]> {
        self.root
            .chaincode
            .as_slice()
            .try_into()
            .map_err(|_| Error::CorruptRecord { offset: OFF_ROOT, what: "root record has no chain code" })
    }

    // ----------------------------------------------------------------- address lookup

    /// Chained address records keyed by chain index (the last entry wins, as in Armory).
    pub fn chained(&self) -> BTreeMap<i64, &AddressRecord> {
        let mut m = BTreeMap::new();
        for e in &self.entries {
            if let Entry::Key { record, .. } = e
                && record.chain_index >= 0
            {
                m.insert(record.chain_index, record);
            }
        }
        m
    }

    pub fn imported(&self) -> Vec<&AddressRecord> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::Key { record, .. } if record.chain_index <= CHAIN_INDEX_IMPORTED => Some(record),
                _ => None,
            })
            .collect()
    }

    /// Record for a chain index; `-1` is the root.
    pub fn record(&self, index: i64) -> Option<&AddressRecord> {
        if index == CHAIN_INDEX_ROOT {
            return Some(&self.root);
        }
        self.entries.iter().rev().find_map(|e| match e {
            Entry::Key { record, .. } if record.chain_index == index => Some(record),
            _ => None,
        })
    }

    pub fn record_by_hash160(&self, h: &[u8; 20]) -> Option<&AddressRecord> {
        if &self.root.addr160 == h {
            return Some(&self.root);
        }
        self.entries.iter().rev().find_map(|e| match e {
            Entry::Key { record, .. } if &record.addr160 == h => Some(record),
            _ => None,
        })
    }

    fn record_mut(&mut self, index: i64) -> Option<&mut AddressRecord> {
        if index == CHAIN_INDEX_ROOT {
            return Some(&mut self.root);
        }
        self.entries.iter_mut().rev().find_map(|e| match e {
            Entry::Key { record, .. } if record.chain_index == index => Some(record),
            _ => None,
        })
    }

    /// Highest chain index computed so far (`lastComputedChainIndex`), or -1.
    pub fn last_computed_index(&self) -> i64 {
        self.chained().keys().next_back().copied().unwrap_or(CHAIN_INDEX_ROOT)
    }

    pub fn address(&self, record: &AddressRecord) -> String {
        self.network.p2pkh_address(&record.addr160)
    }

    // ----------------------------------------------------------------- comments

    /// Address comments; the last entry for a hash wins.
    pub fn address_comments(&self) -> BTreeMap<[u8; 20], String> {
        let mut m = BTreeMap::new();
        for e in &self.entries {
            if let Entry::AddrComment { hash, comment } = e {
                m.insert(*hash, String::from_utf8_lossy(comment).into_owned());
            }
        }
        m
    }

    /// Transaction comments keyed by the internal (little-endian) tx hash.
    pub fn tx_comments(&self) -> BTreeMap<[u8; 32], String> {
        let mut m = BTreeMap::new();
        for e in &self.entries {
            if let Entry::TxComment { hash, comment } = e {
                m.insert(*hash, String::from_utf8_lossy(comment).into_owned());
            }
        }
        m
    }

    /// `setComment`: zero the body of any existing comment for this hash, then append a new one.
    pub fn set_address_comment(&mut self, hash: [u8; 20], comment: &str) {
        for e in &mut self.entries {
            if let Entry::AddrComment { hash: h, comment: c } = e
                && *h == hash
            {
                c.iter_mut().for_each(|b| *b = 0);
            }
        }
        self.entries.push(Entry::AddrComment { hash, comment: comment.as_bytes().to_vec() });
    }

    pub fn set_tx_comment(&mut self, hash: [u8; 32], comment: &str) {
        for e in &mut self.entries {
            if let Entry::TxComment { hash: h, comment: c } = e
                && *h == hash
            {
                c.iter_mut().for_each(|b| *b = 0);
            }
        }
        self.entries.push(Entry::TxComment { hash, comment: comment.as_bytes().to_vec() });
    }

    // ----------------------------------------------------------------- keys

    /// Derive the AES key from a passphrase and verify it against the root record.
    pub fn unlock(&self, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if !self.flags.encrypted {
            return Err(Error::WrongPassphrase);
        }
        let kdf = self.kdf.as_ref().ok_or(Error::CorruptRecord { offset: OFF_KDF, what: "no KDF" })?;
        let key = kdf.derive_key(passphrase)?;
        if self.verify_kdf_key(&key) { Ok(key) } else { Err(Error::WrongPassphrase) }
    }

    /// `verifyEncryptionKey` on the root record.
    pub fn verify_kdf_key(&self, key: &[u8]) -> bool {
        let r = &self.root;
        if !r.flags.encrypted || r.priv_slot.len() != 32 {
            return false;
        }
        let Ok(plain) = aes::decrypt_cfb(key, &r.iv, &r.priv_slot) else { return false };
        let plain = Zeroizing::new(plain);
        match chain::public_key(plain[..].try_into().unwrap()) {
            Ok(pubk) if r.pubkey.len() == 65 => pubk[..] == r.pubkey[..],
            Ok(pubk) => hash160(&pubk) == r.addr160,
            Err(_) => false,
        }
    }

    /// The record's own private key if it is materialised (plain, or encrypted and not pending).
    fn materialised_priv(
        &self,
        r: &AddressRecord,
        key: Option<&[u8]>,
    ) -> Result<Option<Zeroizing<[u8; 32]>>> {
        if !r.flags.has_priv || r.flags.pending || r.priv_slot.len() != 32 {
            return Ok(None);
        }
        if !r.flags.encrypted {
            return Ok(r.plain_priv());
        }
        let key = key.ok_or(Error::Locked)?;
        let p = Zeroizing::new(aes::decrypt_cfb(key, &r.iv, &r.priv_slot)?);
        Ok(Some(Zeroizing::new(p[..].try_into().unwrap())))
    }

    /// Private key of a chain index (`-1` root, `-2..` imported via [`Self::private_key_for`]).
    ///
    /// Pending records ("created while locked") are resolved by chaining forward from the
    /// nearest materialised ancestor, which yields the same key as Armory's unlock logic. The
    /// result is always checked against the stored public key.
    pub fn private_key(&self, index: i64, key: Option<&[u8]>) -> Result<Zeroizing<[u8; 32]>> {
        let target = self.record(index).ok_or(Error::NoSuchIndex(index))?;
        if !target.flags.has_priv {
            return Err(Error::WatchingOnly);
        }
        if target.flags.encrypted && key.is_none() {
            return Err(Error::Locked);
        }
        let cc = self.chaincode()?;
        let mut start = index;
        let mut priv_key = loop {
            let r = self.record(start).ok_or(Error::NoSuchIndex(start))?;
            if let Some(p) = self.materialised_priv(r, key)? {
                break p;
            }
            if start == CHAIN_INDEX_ROOT {
                return Err(Error::CorruptRecord {
                    offset: OFF_ROOT,
                    what: "root has no usable private key",
                });
            }
            start -= 1;
        };
        while start < index {
            priv_key = chain::chained_private_key(&priv_key, &cc)?;
            start += 1;
        }
        self.check_pair(target, &priv_key)?;
        Ok(priv_key)
    }

    /// Private key of any record in the wallet, including imported ones.
    pub fn private_key_for(&self, h: &[u8; 20], key: Option<&[u8]>) -> Result<Zeroizing<[u8; 32]>> {
        let r = self.record_by_hash160(h).ok_or(Error::NoSuchAddress)?;
        if r.is_imported() {
            let p = self.materialised_priv(r, key)?.ok_or(Error::WatchingOnly)?;
            self.check_pair(r, &p)?;
            Ok(p)
        } else {
            self.private_key(r.chain_index, key)
        }
    }

    fn check_pair(&self, r: &AddressRecord, priv_key: &[u8; 32]) -> Result<()> {
        let pubk = chain::public_key(priv_key)?;
        let ok = if r.pubkey.len() == 65 { pubk[..] == r.pubkey[..] } else { hash160(&pubk) == r.addr160 };
        if ok { Ok(()) } else { Err(Error::KeyMismatch(r.chain_index)) }
    }

    /// Check that every chained public key follows from the root (and, when available, every
    /// private key matches). Returns the number of records verified.
    pub fn verify_chain(&self, key: Option<&[u8]>) -> Result<usize> {
        let cc = self.chaincode()?;
        let mut pubk = self
            .root
            .pubkey65()
            .ok_or(Error::CorruptRecord { offset: OFF_ROOT, what: "root has no public key" })?;
        let mut n = 0;
        for (idx, r) in self.chained() {
            if idx != n as i64 {
                return Err(Error::NoSuchIndex(n as i64));
            }
            pubk = chain::chained_public_key(&pubk, &cc)?;
            if r.pubkey65() != Some(pubk) || hash160(&pubk) != r.addr160 {
                return Err(Error::KeyMismatch(idx));
            }
            n += 1;
        }
        if !self.is_watching_only()
            && (!self.flags.encrypted || key.is_some())
            && let Some(last) = self.chained().keys().next_back()
        {
            self.private_key(*last, key)?;
        }
        Ok(n)
    }

    // ----------------------------------------------------------------- extending the chain

    /// Append the next chained address (`extendAddressChain`). With the private key available
    /// (unencrypted, or `key` given) the new record carries its own private key; on a locked
    /// encrypted wallet it becomes a *pending* record, and on a watching-only wallet a
    /// public-key-only record.
    pub fn extend_chain(&mut self, key: Option<&[u8]>) -> Result<&AddressRecord> {
        let cc = self.chaincode()?;
        let last_idx = self.last_computed_index();
        let parent = self.record(last_idx).ok_or(Error::NoSuchIndex(last_idx))?.clone();
        let parent_pub = parent.pubkey65().ok_or(Error::KeyMismatch(last_idx))?;
        let new_pub = chain::chained_public_key(&parent_pub, &cc)?;
        let mut rec = AddressRecord::new(hash160(&new_pub), last_idx + 1);
        rec.chaincode = cc.to_vec();
        rec.pubkey = new_pub.to_vec();
        rec.flags.has_pub = true;
        rec.iv = random_iv();

        let can_sign = parent.flags.has_priv && (!self.flags.encrypted || key.is_some());
        if can_sign {
            let parent_priv = self.private_key(last_idx, key)?;
            let new_priv = chain::chained_private_key(&parent_priv, &cc)?;
            rec.flags.has_priv = true;
            if self.flags.encrypted {
                rec.flags.encrypted = true;
                rec.priv_slot = Zeroizing::new(aes::encrypt_cfb(key.unwrap(), &rec.iv, &new_priv[..])?);
            } else {
                rec.priv_slot = Zeroizing::new(new_priv.to_vec());
            }
        } else if parent.flags.has_priv {
            // Locked: store the nearest materialised ancestor's (IV, ciphertext) pair.
            rec.flags = AddrFlags { has_priv: true, has_pub: true, encrypted: true, pending: true };
            if parent.flags.pending {
                rec.iv = parent.iv.clone();
                rec.priv_slot = parent.priv_slot.clone();
                rec.chain_depth = parent.chain_depth + 1;
            } else {
                rec.iv = parent.iv.clone();
                rec.priv_slot = parent.priv_slot.clone();
                rec.chain_depth = 1;
            }
        } else {
            rec.iv = Vec::new();
        }
        let hash = rec.addr160;
        self.entries.push(Entry::Key { hash, record: rec });
        match self.entries.last() {
            Some(Entry::Key { record, .. }) => Ok(record),
            _ => unreachable!(),
        }
    }

    /// `fillAddressPool`: keep `pool` addresses computed beyond the highest used one.
    pub fn fill_pool(&mut self, pool: usize, key: Option<&[u8]>) -> Result<usize> {
        let ahead = self.last_computed_index() - self.highest_used;
        let to_create = (pool as i64 - ahead).max(0) as usize;
        for _ in 0..to_create {
            self.extend_chain(key)?;
        }
        Ok(to_create)
    }

    /// The address a new receive request would get (`peekNextUnusedAddr`).
    pub fn peek_next_unused(&self) -> Option<&AddressRecord> {
        self.record(self.highest_used + 1)
    }

    /// `getNextUnusedAddress`: advance the highest-used index (refilling the pool) and return
    /// the new index.
    pub fn next_unused(&mut self, pool: usize, key: Option<&[u8]>) -> Result<i64> {
        if self.last_computed_index() - self.highest_used < (pool as i64 - 1).max(1) {
            self.fill_pool(pool, key)?;
        }
        self.highest_used = (self.highest_used + 1).clamp(0, self.last_computed_index());
        self.fill_pool(pool, key)?;
        Ok(self.highest_used)
    }

    /// Resolve every pending record into an ordinary encrypted one (Armory does this on unlock).
    pub fn materialise_pending(&mut self, key: &[u8]) -> Result<usize> {
        let pending: Vec<i64> =
            self.chained().iter().filter(|(_, r)| r.flags.pending).map(|(i, _)| *i).collect();
        for idx in &pending {
            let p = self.private_key(*idx, Some(key))?;
            let iv = random_iv();
            let ct = aes::encrypt_cfb(key, &iv, &p[..])?;
            let r = self.record_mut(*idx).unwrap();
            r.flags.pending = false;
            r.chain_depth = 0;
            r.iv = iv;
            r.priv_slot = Zeroizing::new(ct);
        }
        Ok(pending.len())
    }

    // ----------------------------------------------------------------- encryption

    /// Encrypt, re-key or decrypt every private key (`changeWalletEncryption`).
    ///
    /// * `old_key`: current AES key (required when the wallet is encrypted);
    /// * `new`: `Some((params, passphrase))` to (re-)encrypt, `None` to remove encryption.
    ///
    /// IVs are kept when re-keying and cleared when decrypting, as in Armory.
    pub fn change_encryption(
        &mut self,
        old_key: Option<&[u8]>,
        new: Option<(KdfParams, &[u8])>,
    ) -> Result<()> {
        if self.is_watching_only() {
            return Err(Error::WatchingOnly);
        }
        if self.flags.encrypted {
            let k = old_key.ok_or(Error::Locked)?;
            if !self.verify_kdf_key(k) {
                return Err(Error::WrongPassphrase);
            }
            self.materialise_pending(k)?;
        }
        // Collect every plaintext key first so a failure leaves the wallet untouched.
        let mut plain: Vec<(usize, Zeroizing<[u8; 32]>)> = Vec::new();
        let root_plain = self.materialised_priv(&self.root.clone(), old_key)?.ok_or(Error::WatchingOnly)?;
        for (i, e) in self.entries.iter().enumerate() {
            if let Entry::Key { record, .. } = e
                && let Some(p) = self.materialised_priv(record, old_key)?
            {
                plain.push((i, p));
            }
        }
        let new_key = match &new {
            Some((params, pass)) => Some(params.derive_key(pass)?),
            None => None,
        };
        let apply = |r: &mut AddressRecord, p: &[u8; 32]| -> Result<()> {
            match &new_key {
                Some(k) => {
                    if r.iv.len() != 16 {
                        r.iv = random_iv();
                    }
                    r.flags.encrypted = true;
                    r.priv_slot = Zeroizing::new(aes::encrypt_cfb(k, &r.iv, p)?);
                }
                None => {
                    r.flags.encrypted = false;
                    r.iv = Vec::new();
                    r.priv_slot = Zeroizing::new(p.to_vec());
                }
            }
            Ok(())
        };
        apply(&mut self.root, &root_plain)?;
        for (i, p) in &plain {
            if let Entry::Key { record, .. } = &mut self.entries[*i] {
                apply(record, p)?;
            }
        }
        if let Some((params, _)) = new {
            self.kdf_raw = kdf_block(&params);
            self.kdf = Some(params);
            self.flags.encrypted = true;
        } else {
            // Armory leaves the KDF block in place after decryption.
            self.flags.encrypted = false;
        }
        Ok(())
    }

    // ----------------------------------------------------------------- creation and copies

    /// `createNewWallet`: random root key, chain code derived from it (1.35c), index 0 and the
    /// address pool. With a passphrase the wallet is encrypted using calibrated KDF parameters.
    pub fn create(
        network: LegacyNetwork,
        label: &str,
        description: &str,
        passphrase: Option<(&[u8], Duration)>,
        pool: usize,
        extra_entropy: Option<&[u8]>,
        now: u64,
    ) -> Result<Self> {
        let root_priv = loop {
            let mut k = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut k[..]);
            if let Some(extra) = extra_entropy {
                let mut mix = k.to_vec();
                mix.extend_from_slice(extra);
                let h = armory_crypto::hash::sha256(&mix);
                k.copy_from_slice(&h);
            }
            if chain::public_key(&k).is_ok() {
                break k;
            }
        };
        Self::from_root(network, label, description, &root_priv, None, passphrase, pool, now)
    }

    /// Build a wallet from root material (paper-backup restore). `chaincode` defaults to the
    /// value derived from the root key.
    #[allow(clippy::too_many_arguments)]
    pub fn from_root(
        network: LegacyNetwork,
        label: &str,
        description: &str,
        root_priv: &[u8; 32],
        chaincode: Option<[u8; 32]>,
        passphrase: Option<(&[u8], Duration)>,
        pool: usize,
        now: u64,
    ) -> Result<Self> {
        let cc = chaincode.unwrap_or_else(|| chain::derive_chaincode(root_priv));
        let root_pub = chain::public_key(root_priv)?;
        let first_pub = chain::chained_public_key(&root_pub, &cc)?;
        let mut root = AddressRecord::new(hash160(&root_pub), CHAIN_INDEX_ROOT);
        root.flags = AddrFlags { has_priv: true, has_pub: true, ..Default::default() };
        root.chaincode = cc.to_vec();
        root.priv_slot = Zeroizing::new(root_priv.to_vec());
        root.pubkey = root_pub.to_vec();
        let mut w = Self {
            network,
            version: VERSION_1_35,
            flags: WalletFlags::default(),
            unique_id: chain::wallet_id_bin(&first_pub, network.p2pkh_byte()),
            create_date: now,
            label_raw: [0; LABEL_LEN],
            descr_raw: [0; DESCR_LEN],
            highest_used: -1,
            kdf_raw: [0; 256],
            kdf: None,
            crypto_raw: [0; 256],
            root,
            reserved: vec![0; HEADER_LEN - OFF_RESERVED],
            entries: Vec::new(),
            repaired: false,
        };
        w.set_labels(label, description)?;
        w.extend_chain(None)?;
        if let Some((pass, target)) = passphrase {
            let params = KdfParams::calibrate(target, 32 * 1024 * 1024);
            w.change_encryption(None, Some((params, pass)))?;
            let key = w.unlock(pass)?;
            w.fill_pool(pool, Some(&key))?;
        } else {
            w.fill_pool(pool, None)?;
        }
        Ok(w)
    }

    /// `forkOnlineWallet`: a watching-only copy (no private keys, no KDF).
    pub fn watching_only_copy(&self) -> Self {
        let strip = |r: &AddressRecord| {
            let mut r = r.clone();
            r.flags = AddrFlags { has_pub: r.flags.has_pub, ..Default::default() };
            r.iv = Vec::new();
            r.priv_slot = Zeroizing::new(Vec::new());
            r
        };
        let mut w = self.clone();
        w.flags = WalletFlags { encrypted: false, watching_only: true };
        w.kdf = None;
        w.kdf_raw = [0; 256];
        w.root = strip(&self.root);
        w.entries = self
            .entries
            .iter()
            .filter_map(|e| match e {
                Entry::Key { hash, record } => Some(Entry::Key { hash: *hash, record: strip(record) }),
                Entry::Deleted { .. } | Entry::Unknown(_) => None,
                other => Some(other.clone()),
            })
            .collect();
        let label = format!("{} (Watch)", self.label());
        let descr = format!("{} (Watching-only copy)", self.description());
        let cut = |s: &str, n: usize| {
            let mut end = s.len().min(n);
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            s[..end].to_string()
        };
        w.set_labels(&cut(&label, LABEL_LEN), &cut(&descr, DESCR_LEN)).expect("truncated");
        w
    }

    /// The root private key and chain code, for paper backups.
    pub fn root_secret(&self, key: Option<&[u8]>) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
        Ok((self.private_key(CHAIN_INDEX_ROOT, key)?, self.chaincode()?))
    }

    /// Remove an imported address (`deleteImportedAddress`): the entry becomes a deleted entry of
    /// the same size.
    pub fn remove_imported(&mut self, h: &[u8; 20]) -> Result<()> {
        let pos = self
            .entries
            .iter()
            .position(|e| matches!(e, Entry::Key { record, .. } if &record.addr160 == h))
            .ok_or(Error::NoSuchAddress)?;
        if let Entry::Key { record, .. } = &self.entries[pos]
            && !record.is_imported()
        {
            return Err(Error::NotImported);
        }
        self.entries[pos] = Entry::Deleted { data: vec![0; 20 + RECORD_LEN - 2] };
        Ok(())
    }

    /// Import a single private key (`importExternalAddressData`).
    pub fn import_private_key(&mut self, priv32: &[u8; 32], key: Option<&[u8]>) -> Result<[u8; 20]> {
        if self.is_watching_only() {
            return Err(Error::WatchingOnly);
        }
        let pubk = chain::public_key(priv32)?;
        let h = hash160(&pubk);
        if self.record_by_hash160(&h).is_some() {
            return Ok(h);
        }
        let mut r = AddressRecord::new(h, CHAIN_INDEX_IMPORTED);
        r.flags = AddrFlags { has_priv: true, has_pub: true, ..Default::default() };
        r.chaincode = vec![0xff; 32];
        r.pubkey = pubk.to_vec();
        if self.flags.encrypted {
            let k = key.ok_or(Error::Locked)?;
            r.iv = random_iv();
            r.flags.encrypted = true;
            r.priv_slot = Zeroizing::new(aes::encrypt_cfb(k, &r.iv, priv32)?);
        } else {
            r.priv_slot = Zeroizing::new(priv32.to_vec());
        }
        self.entries.push(Entry::Key { hash: h, record: r });
        Ok(h)
    }
}
