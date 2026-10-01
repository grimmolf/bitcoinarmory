//! Lockboxes (multisig).
//!
//! * **Modern lockboxes**: `wsh(sortedmulti(M, cosigner xpubs))`, cosigner keys from the BIP48
//!   script-type-2 path `m/48h/<coin>h/0h/2h`, one file per lockbox.
//! * **Armory 0.93 lockboxes** (spec 04): `LOCKBOX` ASCII blocks and `multisigs.txt`
//!   (binary versions 0 and 1), imported as `sh(multi(M, raw keys))` so existing funds can be
//!   watched and spent. `PUBLICKEY` blocks are read for key exchange.

use std::str::FromStr;

use base64::Engine;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::key::Secp256k1;
use bitcoin::script::Builder;
use bitcoin::{Address, Network, ScriptBuf, opcodes};
use serde::{Deserialize, Serialize};

use crate::descriptor::with_checksum;
use crate::modern::{ModernError, ModernWallet, Result, Unlocked, legacy_network};

fn invalid(e: impl std::fmt::Display) -> ModernError {
    ModernError::Invalid(e.to_string())
}

// ===================================================================== Armory 0.93 formats

/// One ASCII-armored block: `=====<KIND>-<ID>====` / base64 / `=====`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmoredBlock {
    pub kind: String,
    pub id: String,
    pub data: Vec<u8>,
}

/// Parse every Armory armored block in `text` (any width, any line endings).
pub fn parse_armored(text: &str) -> Result<Vec<ArmoredBlock>> {
    let mut out = Vec::new();
    let mut cur: Option<(String, String, String)> = None;
    for tok in text.split_whitespace() {
        let is_frame = tok.starts_with("=====");
        let all_eq = tok.chars().all(|c| c == '=');
        match (&mut cur, is_frame, all_eq) {
            (None, true, false) => {
                let head = tok.trim_matches('=');
                let (kind, id) = head.rsplit_once('-').unwrap_or((head, ""));
                cur = Some((kind.to_string(), id.to_string(), String::new()));
            }
            (Some(_), true, true) => {
                let (kind, id, b64) = cur.take().unwrap();
                let data = base64::engine::general_purpose::STANDARD.decode(b64).map_err(invalid)?;
                out.push(ArmoredBlock { kind, id, data });
            }
            (Some((_, _, b)), false, _) => b.push_str(tok),
            _ => {}
        }
    }
    Ok(out)
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.b.get(self.p..self.p + n).ok_or_else(|| invalid("truncated block"))?;
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn varint(&mut self) -> Result<u64> {
        Ok(match self.u8()? {
            0xfd => u64::from(u16::from_le_bytes(self.take(2)?.try_into().unwrap())),
            0xfe => u64::from(self.u32()?),
            0xff => self.u64()?,
            n => u64::from(n),
        })
    }
    fn varstr(&mut self) -> Result<&'a [u8]> {
        let n = self.varint()? as usize;
        self.take(n)
    }
}

fn magic(network: Network) -> [u8; 4] {
    legacy_network(network).magic()
}

/// A key shared by a lockbox participant (`DecoratedPublicKey`, spec 04 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoratedPublicKey {
    pub pubkey: Vec<u8>,
    pub comment: String,
}

fn parse_dpk(data: &[u8], network: Network) -> Result<DecoratedPublicKey> {
    let mut r = Reader { b: data, p: 0 };
    let _version = r.u32()?;
    if r.take(4)? != magic(network) {
        return Err(invalid("public key block is for another network"));
    }
    let pubkey = r.varstr()?.to_vec();
    let comment = String::from_utf8_lossy(r.varstr()?).into_owned();
    if pubkey.len() != 33 && pubkey.len() != 65 {
        return Err(invalid("public key must be 33 or 65 bytes"));
    }
    Ok(DecoratedPublicKey { pubkey, comment })
}

/// `pubKeyID`: first 12 characters of the key's P2PKH address.
pub fn pubkey_id(pubkey: &[u8], network: Network) -> String {
    let a = legacy_network(network).p2pkh_address(&armory_crypto::hash::hash160(pubkey));
    a[..12].to_string()
}

/// An Armory 0.93 lockbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyLockbox {
    pub id: String,
    pub version: u32,
    pub created: u64,
    pub name: String,
    pub description: String,
    pub m: u8,
    /// Keys in script order (sorted by raw bytes), with their comments.
    pub keys: Vec<DecoratedPublicKey>,
}

/// Bare multisig script with keys sorted by raw bytes (`pubkeylist_to_multisig_script`).
pub fn legacy_multisig_script(m: u8, keys: &[Vec<u8>]) -> ScriptBuf {
    let mut sorted = keys.to_vec();
    sorted.sort();
    let mut b = Builder::new().push_int(i64::from(m));
    for k in &sorted {
        b = b.push_slice(bitcoin::script::PushBytesBuf::try_from(k.clone()).unwrap());
    }
    b.push_int(sorted.len() as i64).push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script()
}

/// Lockbox ID: `base58(hash160(MAGIC || 0xfe || M || N || sorted(hash160(keys))))[1..9]`.
pub fn legacy_lockbox_id(m: u8, keys: &[Vec<u8>], network: Network) -> String {
    let mut hashes: Vec<[u8; 20]> = keys.iter().map(|k| armory_crypto::hash::hash160(k)).collect();
    hashes.sort();
    let mut data = magic(network).to_vec();
    data.extend_from_slice(&[0xfe, m, keys.len() as u8]);
    for h in hashes {
        data.extend_from_slice(&h);
    }
    let b58 = armory_crypto::base58::encode(&armory_crypto::hash::hash160(&data));
    b58.chars().skip(1).take(8).collect()
}

/// `(M, keys)` of a bare multisig script.
pub fn script_keys(script: &[u8]) -> Result<(u8, Vec<Vec<u8>>)> {
    let s = ScriptBuf::from_bytes(script.to_vec());
    let ins: Vec<_> = s.instructions().collect::<std::result::Result<_, _>>().map_err(invalid)?;
    let num = |i: &bitcoin::script::Instruction| match i {
        bitcoin::script::Instruction::Op(op) => {
            let v = op.to_u8();
            (0x51..=0x60).contains(&v).then(|| v - 0x50)
        }
        _ => None,
    };
    if ins.len() < 4 {
        return Err(invalid("not a multisig script"));
    }
    let m = num(&ins[0]).ok_or_else(|| invalid("not a multisig script"))?;
    let keys: Vec<Vec<u8>> = ins[1..ins.len() - 2]
        .iter()
        .map(|i| match i {
            bitcoin::script::Instruction::PushBytes(p) => Ok(p.as_bytes().to_vec()),
            _ => Err(invalid("not a multisig script")),
        })
        .collect::<Result<_>>()?;
    Ok((m, keys))
}

impl LegacyLockbox {
    /// Parse a `LOCKBOX` block body (binary version 0 or 1) and check its ID.
    pub fn parse(data: &[u8], expected_id: &str, network: Network) -> Result<Self> {
        let mut r = Reader { b: data, p: 0 };
        let version = r.u32()?;
        if r.take(4)? != magic(network) {
            return Err(invalid("lockbox is for another network"));
        }
        let created = r.u64()?;
        let (name, description, m, mut keys);
        if version == 0 {
            let script = r.varstr()?.to_vec();
            name = String::from_utf8_lossy(r.varstr()?).into_owned();
            description = String::from_utf8_lossy(r.varstr()?).into_owned();
            let ncom = r.u32()? as usize;
            let mut comments = Vec::new();
            for _ in 0..ncom {
                comments.push(String::from_utf8_lossy(r.varstr()?).into_owned());
            }
            let (mm, ks) = script_keys(&script)?;
            m = mm;
            keys = ks
                .into_iter()
                .enumerate()
                .map(|(i, pubkey)| DecoratedPublicKey {
                    pubkey,
                    comment: comments.get(i).cloned().unwrap_or_default(),
                })
                .collect::<Vec<_>>();
        } else {
            name = String::from_utf8_lossy(r.varstr()?).into_owned();
            description = String::from_utf8_lossy(r.varstr()?).into_owned();
            m = r.u8()?;
            let n = r.u8()?;
            keys = Vec::new();
            for _ in 0..n {
                keys.push(parse_dpk(r.varstr()?, network)?);
            }
        }
        // Readers sort by key bytes (stable) so key i matches script key i.
        keys.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
        let raw: Vec<Vec<u8>> = keys.iter().map(|k| k.pubkey.clone()).collect();
        let id = legacy_lockbox_id(m, &raw, network);
        if !expected_id.is_empty() && id != expected_id {
            return Err(invalid(format!(
                "lockbox ID mismatch: block says {expected_id}, contents give {id}"
            )));
        }
        Ok(Self { id, version, created, name, description, m, keys })
    }

    pub fn script(&self) -> ScriptBuf {
        legacy_multisig_script(self.m, &self.keys.iter().map(|k| k.pubkey.clone()).collect::<Vec<_>>())
    }

    pub fn p2sh_address(&self, network: Network) -> Address {
        Address::p2sh(&self.script(), network).expect("multisig fits P2SH")
    }
}

/// Every lockbox in a text (a `multisigs.txt` or exported `.lockbox.def` blocks).
pub fn read_legacy_lockboxes(text: &str, network: Network) -> Result<Vec<LegacyLockbox>> {
    parse_armored(text)?
        .into_iter()
        .filter(|b| b.kind == "LOCKBOX")
        .map(|b| LegacyLockbox::parse(&b.data, &b.id, network))
        .collect()
}

/// Every `PUBLICKEY` block in a text.
pub fn read_public_keys(text: &str, network: Network) -> Result<Vec<DecoratedPublicKey>> {
    parse_armored(text)?
        .into_iter()
        .filter(|b| b.kind == "PUBLICKEY")
        .map(|b| parse_dpk(&b.data, network))
        .collect()
}

// ===================================================================== modern lockboxes

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockboxKind {
    /// `wsh(sortedmulti(M, xpub/<0;1>/*...))`.
    WshSortedMulti,
    /// Imported Armory 0.93 lockbox: `sh(multi(M, raw keys))`, one fixed address.
    LegacyP2sh,
}

/// A lockbox file (`<id>.lockbox`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lockbox {
    pub format: String,
    pub version: u32,
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub network: Network,
    pub kind: LockboxKind,
    pub m: u8,
    /// Modern: `[fp/48h/coin'h/0h/2h]xpub...`; legacy: hex public keys in script order.
    pub keys: Vec<String>,
    /// Comments per key.
    #[serde(default)]
    pub key_comments: Vec<String>,
    pub created: u64,
    #[serde(default)]
    pub birthday: u64,
    #[serde(default)]
    pub next_receive: u32,
    #[serde(default)]
    pub next_change: u32,
    /// The Armory 0.93 lockbox ID for imported lockboxes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_id: Option<String>,
}

pub const LOCKBOX_FORMAT: &str = "armory-lockbox";

fn parse_key_expr(k: &str) -> Result<(Option<(Fingerprint, DerivationPath)>, Xpub)> {
    let (origin, rest) = match k.strip_prefix('[') {
        Some(r) => {
            let (o, x) = r.split_once(']').ok_or_else(|| invalid(format!("bad key {k}")))?;
            let (fp, path) = o.split_once('/').unwrap_or((o, ""));
            let fp = Fingerprint::from_str(fp).map_err(invalid)?;
            let path = DerivationPath::from_str(&format!("m/{}", path.replace('h', "'"))).map_err(invalid)?;
            (Some((fp, path)), x)
        }
        None => (None, k),
    };
    let rest = rest.trim_end_matches("/<0;1>/*").trim_end_matches("/*");
    Ok((origin, Xpub::from_str(rest).map_err(|e| invalid(format!("bad xpub in {k}: {e}")))?))
}

/// BIP48 multisig cosigner key of a wallet: `[fp/48h/<coin>h/<account>h/2h]xpub`.
pub fn cosigner_key(w: &ModernWallet, u: &Unlocked, account: u32) -> Result<String> {
    let secp = Secp256k1::new();
    let coin = if w.network == Network::Bitcoin { 0 } else { 1 };
    let path_s = format!("48h/{coin}h/{account}h/2h");
    let path = DerivationPath::from_str(&format!("m/{}", path_s.replace('h', "'"))).map_err(invalid)?;
    let x = Xpub::from_priv(&secp, &u.master().derive_priv(&secp, &path).map_err(invalid)?);
    Ok(format!("[{}/{path_s}]{x}", w.id))
}

impl Lockbox {
    /// A new M-of-N SegWit lockbox from cosigner keys.
    pub fn new_modern(
        network: Network,
        name: &str,
        m: u8,
        keys: Vec<String>,
        comments: Vec<String>,
        now: u64,
    ) -> Result<Self> {
        if keys.is_empty() || m == 0 || usize::from(m) > keys.len() || keys.len() > 15 {
            return Err(invalid("need 1 <= M <= N <= 15"));
        }
        for k in &keys {
            let (_, x) = parse_key_expr(k)?;
            if x.network != network.into() {
                return Err(invalid(format!("key {k} is for another network")));
            }
        }
        let mut lb = Self {
            format: LOCKBOX_FORMAT.into(),
            version: 1,
            id: String::new(),
            name: name.into(),
            description: String::new(),
            network,
            kind: LockboxKind::WshSortedMulti,
            m,
            keys,
            key_comments: comments,
            created: now,
            birthday: now.saturating_sub(7200),
            next_receive: 0,
            next_change: 0,
            legacy_id: None,
        };
        lb.id = lb.compute_id();
        Ok(lb)
    }

    /// Import an Armory 0.93 lockbox.
    pub fn from_legacy(l: &LegacyLockbox, network: Network) -> Self {
        let mut lb = Self {
            format: LOCKBOX_FORMAT.into(),
            version: 1,
            id: String::new(),
            name: l.name.clone(),
            description: l.description.clone(),
            network,
            kind: LockboxKind::LegacyP2sh,
            m: l.m,
            keys: l.keys.iter().map(|k| hex::encode(&k.pubkey)).collect(),
            key_comments: l.keys.iter().map(|k| k.comment.clone()).collect(),
            created: l.created,
            birthday: 0,
            next_receive: 1,
            next_change: 0,
            legacy_id: Some(l.id.clone()),
        };
        lb.id = l.id.clone();
        lb
    }

    fn compute_id(&self) -> String {
        let d = self.descriptor_body(0);
        hex::encode(&armory_crypto::hash::sha256(d.as_bytes())[..4])
    }

    fn descriptor_body(&self, branch: u32) -> String {
        match self.kind {
            LockboxKind::WshSortedMulti => {
                let ks: Vec<String> = self
                    .keys
                    .iter()
                    .map(|k| format!("{}/{branch}/*", k.trim_end_matches("/<0;1>/*").trim_end_matches("/*")))
                    .collect();
                format!("wsh(sortedmulti({},{}))", self.m, ks.join(","))
            }
            LockboxKind::LegacyP2sh => format!("sh(multi({},{}))", self.m, self.keys.join(",")),
        }
    }

    /// Descriptors with checksums (receive and change for SegWit lockboxes).
    pub fn descriptors(&self) -> Vec<String> {
        match self.kind {
            LockboxKind::WshSortedMulti => (0..2).map(|b| with_checksum(&self.descriptor_body(b))).collect(),
            LockboxKind::LegacyP2sh => vec![with_checksum(&self.descriptor_body(0))],
        }
    }

    /// Witness or redeem script for an address.
    pub fn script(&self, branch: u32, index: u32) -> Result<ScriptBuf> {
        match self.kind {
            LockboxKind::WshSortedMulti => {
                let secp = Secp256k1::verification_only();
                let mut keys = Vec::new();
                for k in &self.keys {
                    let (_, x) = parse_key_expr(k)?;
                    let c = x
                        .derive_pub(
                            &secp,
                            &[
                                ChildNumber::from_normal_idx(branch).map_err(invalid)?,
                                ChildNumber::from_normal_idx(index).map_err(invalid)?,
                            ],
                        )
                        .map_err(invalid)?;
                    keys.push(c.public_key.serialize().to_vec());
                }
                keys.sort();
                let mut b = Builder::new().push_int(i64::from(self.m));
                for k in keys {
                    b = b.push_slice(bitcoin::script::PushBytesBuf::try_from(k).unwrap());
                }
                Ok(b.push_int(self.keys.len() as i64)
                    .push_opcode(opcodes::all::OP_CHECKMULTISIG)
                    .into_script())
            }
            LockboxKind::LegacyP2sh => {
                let raw: Vec<Vec<u8>> =
                    self.keys.iter().map(|k| hex::decode(k).map_err(invalid)).collect::<Result<_>>()?;
                Ok(legacy_multisig_script(self.m, &raw))
            }
        }
    }

    pub fn address(&self, branch: u32, index: u32) -> Result<Address> {
        let s = self.script(branch, index)?;
        Ok(match self.kind {
            LockboxKind::WshSortedMulti => Address::p2wsh(&s, self.network),
            LockboxKind::LegacyP2sh => Address::p2sh(&s, self.network).map_err(invalid)?,
        })
    }

    pub fn next_receive(&mut self) -> Result<Address> {
        if self.kind == LockboxKind::LegacyP2sh {
            return self.address(0, 0);
        }
        let a = self.address(0, self.next_receive)?;
        self.next_receive += 1;
        Ok(a)
    }

    pub fn next_change(&mut self) -> Result<Address> {
        if self.kind == LockboxKind::LegacyP2sh {
            return self.address(0, 0);
        }
        let a = self.address(1, self.next_change)?;
        self.next_change += 1;
        Ok(a)
    }

    /// Scripts of handed-out addresses plus `gap` more (to recognise lockbox outputs).
    pub fn scripts(&self, gap: u32) -> Vec<ScriptBuf> {
        match self.kind {
            LockboxKind::LegacyP2sh => {
                self.address(0, 0).map(|a| vec![a.script_pubkey()]).unwrap_or_default()
            }
            LockboxKind::WshSortedMulti => [(0, self.next_receive), (1, self.next_change)]
                .iter()
                .flat_map(|(b, n)| {
                    (0..n + gap).filter_map(move |i| self.address(*b, i).ok().map(|a| a.script_pubkey()))
                })
                .collect(),
        }
    }

    /// Fingerprints of the cosigners (modern lockboxes).
    pub fn cosigner_fingerprints(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter_map(|k| parse_key_expr(k).ok().and_then(|(o, _)| o.map(|(f, _)| f.to_string())))
            .collect()
    }

    pub fn file_name(&self) -> String {
        format!("{}.lockbox", self.id)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_json(b: &[u8]) -> Result<Self> {
        let lb: Lockbox = serde_json::from_slice(b).map_err(|_| invalid("not a lockbox file"))?;
        if lb.format != LOCKBOX_FORMAT {
            return Err(invalid("not a lockbox file"));
        }
        if lb.kind == LockboxKind::WshSortedMulti && lb.compute_id() != lb.id {
            return Err(invalid("lockbox ID does not match its keys"));
        }
        Ok(lb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        let p =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy/multisigs.txt");
        std::fs::read_to_string(p).unwrap()
    }

    // spec 04 §6.1: the four TIAB lockboxes (all version 0, testnet).
    #[test]
    fn multisigs_txt_fixture() {
        let lbs = read_legacy_lockboxes(&fixture(), Network::Testnet).unwrap();
        let got: Vec<(String, u8, usize, String)> = lbs
            .iter()
            .map(|l| (l.id.clone(), l.m, l.keys.len(), l.p2sh_address(Network::Testnet).to_string()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("xxfz2Xk9".into(), 2, 3, "2NEGuMGuJ4meQsUCMYPT9qmCZtpXAKCicu4".into()),
                ("YQR7xnZj".into(), 1, 2, "2N3pg4jUYNGxvZmay4SLSmNLPVi8oDf2CHG".into()),
                ("rcEKCpQY".into(), 2, 2, "2N8J15VSbNfAajBgmtpshbbcLDuZ3PrmTdD".into()),
                ("ZprWK4fA".into(), 4, 7, "2Mz6THSBFmLNGrMAqcdy3g8gpH6jrVBWqu7".into()),
            ]
        );
        assert_eq!(lbs[0].name, "First Lockbox");
        assert_eq!(lbs[0].keys[0].comment, "Primary Wallet (GDHFnMQ2)");
        assert!(lbs.iter().all(|l| l.version == 0));
        // As a modern lockbox file: one P2SH address, sh(multi()) descriptor.
        let lb = Lockbox::from_legacy(&lbs[3], Network::Testnet);
        assert_eq!(lb.address(0, 0).unwrap().to_string(), "2Mz6THSBFmLNGrMAqcdy3g8gpH6jrVBWqu7");
        assert!(lb.descriptors()[0].starts_with("sh(multi(4,04"));
        // Wrong network is refused.
        assert!(read_legacy_lockboxes(&fixture(), Network::Bitcoin).is_err());
    }

    // spec 04 Appendix B: version-1 lockbox and public-key blocks from testMultisig.py.
    #[test]
    fn test_suite_blocks() {
        let lb = "=====LOCKBOX-7mtvkCTa===========================================================
AQAAAAsRCQclhKNTAAAAAAtTYW1wbGUgMm9mMwACA2ABAAAACxEJB0EEIyFPYevSaNGQ275VH4kVFzOv
AT4T4VvN3mX9c0IckLqLraWJURVGdqy2FhAKOIWy/bJjD0c3ovHA7r55B4EpARJLZXkgIzEgaW4gdGhl
IGxpc3QAAABWAQAAAAsRCQdBBMWU5+Df9QeQfI0i+TRNXiImnOGzoIAyVGKhEpa20uN95t7eEN+gOaip
pJmGbFxQew0C1LTqlUn4C4oaNIwDkroIS2V5ICMyISAAAABkAQAAAAsRCQdBBM4V2NEr/b6GvTRXiJEW
XMNcxLQuXd9P6on1hIfnX0hROwi+FB6c4NExF5ddt8mZwLFQ+Dc3ZNC8tfuIjYZGjaMWS2V5IHdpdGgg
dW5pY29kZSBkYXRhIQAAAA==
================================================================================";
        let l = read_legacy_lockboxes(lb, Network::Testnet).unwrap();
        assert_eq!((l[0].id.as_str(), l[0].m, l[0].keys.len(), l[0].version), ("7mtvkCTa", 2, 3, 1));
        assert_eq!(l[0].name, "Sample 2of3");
        assert!(l.iter().flat_map(|x| &x.keys).any(|k| k.comment == "Key with unicode data!"));
        let dpk = "=====PUBLICKEY-mqjMCZC4BFRm=====================================================
AQAAAAsRCQdBBCMhT2Hr0mjRkNu+VR+JFRczrwE+E+Fbzd5l/XNCHJC6i62liVEVRnasthYQCjiFsv2y
Yw9HN6LxwO6+eQeBKQEcdGhpcyBpcyBhIHVzZWxlc3MgY29tbWVudCFAIQAAAA==
================================================================================";
        let k = read_public_keys(dpk, Network::Testnet).unwrap();
        assert_eq!(pubkey_id(&k[0].pubkey, Network::Testnet), "mqjMCZC4BFRm");
        assert_eq!(k[0].comment, "this is a useless comment!@!");
    }

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn modern_lockbox() {
        let w1 = ModernWallet::restore(Network::Testnet, "a", ABANDON, "", None, 0).unwrap().wallet;
        let w2 = ModernWallet::generate(Network::Testnet, "b", 12, "", None, None, 0).unwrap().wallet;
        let k1 = cosigner_key(&w1, &w1.unlock(None).unwrap(), 0).unwrap();
        let k2 = cosigner_key(&w2, &w2.unlock(None).unwrap(), 0).unwrap();
        assert!(k1.starts_with("[73c5da0a/48h/1h/0h/2h]tpub"));
        let mut lb =
            Lockbox::new_modern(Network::Testnet, "Joint", 2, vec![k1.clone(), k2.clone()], vec![], 0)
                .unwrap();
        // Key order does not change the addresses (sortedmulti).
        let lb2 = Lockbox::new_modern(Network::Testnet, "Joint", 2, vec![k2, k1], vec![], 0).unwrap();
        assert_eq!(lb.address(0, 5).unwrap(), lb2.address(0, 5).unwrap());
        let a = lb.next_receive().unwrap();
        assert!(a.to_string().starts_with("tb1q") && a.to_string().len() == 62);
        assert!(lb.descriptors()[0].starts_with("wsh(sortedmulti(2,[73c5da0a/48h/1h/0h/2h]tpub"));
        assert!(lb.descriptors()[1].contains("/1/*"));
        let back = Lockbox::from_json(&lb.to_json().unwrap()).unwrap();
        assert_eq!(back, lb);
        assert!(Lockbox::new_modern(Network::Testnet, "x", 3, vec![lb.keys[0].clone()], vec![], 0).is_err());
    }
}
