//! Signed messages.
//!
//! * **BIP137 / Bitcoin-Qt** compact signatures (65 bytes, base64) for P2PKH (uncompressed and
//!   compressed keys, as Armory 0.93 produced) and P2WPKH (header 39-42).
//! * **BIP322 "simple"** signatures for P2WPKH and P2TR (key path), the modern standard.
//! * **Armory 0.93 signed blocks** (`jasvet.py`, spec 03 §5): clearsign
//!   (`BITCOIN SIGNED MESSAGE` + `BITCOIN SIGNATURE`) and base64 (`BITCOIN MESSAGE`) blocks
//!   with Armory's CRC-24 (emitted least-significant byte first). Both are verified; clearsign
//!   blocks can also be produced.

use base64::Engine;
use bitcoin::consensus::encode;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::{CompressedPublicKey, Secp256k1, TapTweak};
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{Message, PublicKey, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Address, Amount, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    opcodes, script, transaction,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageError {
    #[error("malformed signature")]
    Malformed,
    #[error("signature does not match the address")]
    Mismatch,
    #[error("unsupported address type for {0}")]
    Unsupported(&'static str),
    #[error("signed block checksum (CRC-24) mismatch")]
    Checksum,
    #[error("unknown signed block type {0:?}")]
    UnknownBlock(String),
}

pub type Result<T> = std::result::Result<T, MessageError>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// `hash256("\x18Bitcoin Signed Message:\n" || varint(len) || msg)`.
pub fn bitcoin_msg_hash(msg: &[u8]) -> [u8; 32] {
    let mut data = b"\x18Bitcoin Signed Message:\n".to_vec();
    data.extend(encode::serialize(&encode::VarInt(msg.len() as u64)));
    data.extend_from_slice(msg);
    armory_crypto::hash::hash256(&data)
}

/// BIP137 header bases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactKind {
    P2pkhUncompressed,
    P2pkhCompressed,
    P2shP2wpkh,
    P2wpkh,
}

impl CompactKind {
    fn base(self) -> u8 {
        match self {
            CompactKind::P2pkhUncompressed => 27,
            CompactKind::P2pkhCompressed => 31,
            CompactKind::P2shP2wpkh => 35,
            CompactKind::P2wpkh => 39,
        }
    }
}

/// BIP137 compact signature, base64.
pub fn sign_compact(sk: &SecretKey, kind: CompactKind, msg: &[u8]) -> String {
    let secp = Secp256k1::signing_only();
    let m = Message::from_digest(bitcoin_msg_hash(msg));
    let sig = secp.sign_ecdsa_recoverable(&m, sk);
    let (rec, rs) = sig.serialize_compact();
    let mut out = vec![kind.base() + rec.to_i32() as u8];
    out.extend_from_slice(&rs);
    B64.encode(out)
}

/// Recover the public key of a compact signature: `(key, compressed, header)`.
pub fn recover_compact(sig_b64: &str, msg: &[u8]) -> Result<(PublicKey, bool, u8)> {
    let raw = B64.decode(sig_b64.trim()).map_err(|_| MessageError::Malformed)?;
    if raw.len() != 65 || !(27..=42).contains(&raw[0]) {
        return Err(MessageError::Malformed);
    }
    let header = raw[0];
    let rec = RecoveryId::from_i32(((header - 27) % 4) as i32).map_err(|_| MessageError::Malformed)?;
    let sig = RecoverableSignature::from_compact(&raw[1..], rec).map_err(|_| MessageError::Malformed)?;
    let pk = Secp256k1::verification_only()
        .recover_ecdsa(&Message::from_digest(bitcoin_msg_hash(msg)), &sig)
        .map_err(|_| MessageError::Malformed)?;
    Ok((pk, header >= 31, header))
}

/// The P2PKH address (base58 version byte `p2pkh`) a compact signature recovers to — what Armory's
/// signed-block verifier displayed.
pub fn recovered_p2pkh(sig_b64: &str, msg: &[u8], p2pkh_version: u8) -> Result<String> {
    let (pk, compressed, _) = recover_compact(sig_b64, msg)?;
    let bytes = if compressed { pk.serialize().to_vec() } else { pk.serialize_uncompressed().to_vec() };
    let mut payload = vec![p2pkh_version];
    payload.extend_from_slice(&armory_crypto::hash::hash160(&bytes));
    Ok(armory_crypto::base58::encode_check(&payload))
}

// ------------------------------------------------------------------------- BIP322

/// BIP322 tagged message hash.
pub fn bip322_msg_hash(msg: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(b"BIP0322-signed-message").to_byte_array();
    let mut data = tag.to_vec();
    data.extend_from_slice(&tag);
    data.extend_from_slice(msg);
    sha256::Hash::hash(&data).to_byte_array()
}

fn to_spend(spk: &ScriptBuf, msg: &[u8]) -> Transaction {
    let script_sig =
        script::Builder::new().push_opcode(opcodes::OP_0).push_slice(bip322_msg_hash(msg)).into_script();
    Transaction {
        version: transaction::Version(0),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: bitcoin::Txid::all_zeros(), vout: 0xFFFF_FFFF },
            script_sig,
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::ZERO, script_pubkey: spk.clone() }],
    }
}

fn to_sign(to_spend: &Transaction) -> Transaction {
    Transaction {
        version: transaction::Version(0),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: to_spend.compute_txid(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        // A bare OP_RETURN (`new_op_return([])` would add an empty push).
        output: vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(vec![0x6a]) }],
    }
}

/// BIP322 "simple" signature (base64 of the serialized witness) for P2WPKH or P2TR.
pub fn sign_bip322(sk: &SecretKey, address: &Address, msg: &[u8]) -> Result<String> {
    let secp = Secp256k1::new();
    let spk = address.script_pubkey();
    let spend = to_spend(&spk, msg);
    let sign_tx = to_sign(&spend);
    let mut cache = SighashCache::new(&sign_tx);
    let witness = if spk.is_p2wpkh() {
        let pk = CompressedPublicKey(sk.public_key(&secp));
        let h = cache
            .p2wpkh_signature_hash(0, &spk, Amount::ZERO, EcdsaSighashType::All)
            .map_err(|_| MessageError::Malformed)?;
        let sig = bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa(&Message::from_digest(h.to_byte_array()), sk),
            sighash_type: EcdsaSighashType::All,
        };
        Witness::from_slice(&[sig.to_vec(), pk.to_bytes().to_vec()])
    } else if spk.is_p2tr() {
        let kp = bitcoin::key::Keypair::from_secret_key(&secp, sk);
        let tweaked = kp.tap_tweak(&secp, None);
        let prevouts = [spend.output[0].clone()];
        let h = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .map_err(|_| MessageError::Malformed)?;
        let sig = secp.sign_schnorr(&Message::from_digest(h.to_byte_array()), &tweaked.to_keypair());
        Witness::from_slice(&[sig.as_ref().to_vec()])
    } else {
        return Err(MessageError::Unsupported("BIP322 simple signing"));
    };
    Ok(B64.encode(encode::serialize(&witness)))
}

/// Verify a BIP322 "simple" signature for P2WPKH or P2TR.
pub fn verify_bip322(address: &Address, msg: &[u8], sig_b64: &str) -> Result<()> {
    let secp = Secp256k1::verification_only();
    let raw = B64.decode(sig_b64.trim()).map_err(|_| MessageError::Malformed)?;
    let witness: Witness = encode::deserialize(&raw).map_err(|_| MessageError::Malformed)?;
    let spk = address.script_pubkey();
    let spend = to_spend(&spk, msg);
    let sign_tx = to_sign(&spend);
    let mut cache = SighashCache::new(&sign_tx);
    let items: Vec<&[u8]> = witness.iter().collect();
    if spk.is_p2wpkh() {
        let [sig, pk] = items[..] else { return Err(MessageError::Malformed) };
        let sig = bitcoin::ecdsa::Signature::from_slice(sig).map_err(|_| MessageError::Malformed)?;
        let pk = CompressedPublicKey::from_slice(pk).map_err(|_| MessageError::Malformed)?;
        if ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()) != spk {
            return Err(MessageError::Mismatch);
        }
        let h = cache
            .p2wpkh_signature_hash(0, &spk, Amount::ZERO, sig.sighash_type)
            .map_err(|_| MessageError::Malformed)?;
        secp.verify_ecdsa(&Message::from_digest(h.to_byte_array()), &sig.signature, &pk.0)
            .map_err(|_| MessageError::Mismatch)
    } else if spk.is_p2tr() {
        let [sig] = items[..] else { return Err(MessageError::Malformed) };
        let sig = bitcoin::taproot::Signature::from_slice(sig).map_err(|_| MessageError::Malformed)?;
        let prevouts = [spend.output[0].clone()];
        let h = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), sig.sighash_type)
            .map_err(|_| MessageError::Malformed)?;
        let key =
            bitcoin::XOnlyPublicKey::from_slice(&spk.as_bytes()[2..]).map_err(|_| MessageError::Malformed)?;
        secp.verify_schnorr(&sig.signature, &Message::from_digest(h.to_byte_array()), &key)
            .map_err(|_| MessageError::Mismatch)
    } else {
        Err(MessageError::Unsupported("BIP322 simple verification"))
    }
}

/// Verify any supported signature for an address: BIP137 compact (P2PKH with either key form,
/// P2WPKH and P2SH-P2WPKH headers, Electrum-style headers accepted) or BIP322 simple.
pub fn verify(address: &Address, msg: &[u8], sig_b64: &str) -> Result<()> {
    if let Ok((pk, compressed, _)) = recover_compact(sig_b64, msg) {
        let spk = address.script_pubkey();
        let ok = if spk.is_p2pkh() {
            let bytes =
                if compressed { pk.serialize().to_vec() } else { pk.serialize_uncompressed().to_vec() };
            spk == ScriptBuf::new_p2pkh(&PubkeyHash::hash(&bytes))
        } else if !compressed {
            false // SegWit keys are always compressed
        } else if spk.is_p2wpkh() {
            spk == ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash())
        } else if spk.is_p2sh() {
            let inner = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
            spk == ScriptBuf::new_p2sh(&inner.script_hash())
        } else {
            false
        };
        return if ok { Ok(()) } else { Err(MessageError::Mismatch) };
    }
    verify_bip322(address, msg, sig_b64)
}

// ------------------------------------------------------------------------- Armory 0.93 blocks

/// Armory's `FormatText`: CRLF line ends, trailing whitespace stripped, no final newline;
/// dash-escaping (`- `) of lines starting with `-` unless `sig_context`.
pub fn format_text(t: &str, sig_context: bool) -> String {
    let lines: Vec<String> = t
        .split('\n')
        .map(|l| {
            let l = l.trim_end_matches([' ', '\r', '\t']);
            let l = if !sig_context && l.starts_with('-') { format!("- {l}") } else { l.to_string() };
            format!("{l}\r")
        })
        .collect();
    let mut s = lines.join("\n");
    s.truncate(s.len().saturating_sub(1)); // drop the final '\r' (the '\n' is not there)
    s
}

/// OpenPGP CRC-24, bytes emitted least-significant first as Armory does.
pub fn armory_crc24(data: &[u8]) -> [u8; 3] {
    let mut crc: u32 = 0xB704CE;
    for b in data {
        crc ^= u32::from(*b) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= 0x1864CFB;
            }
        }
    }
    let c = crc & 0xFFFFFF;
    [(c & 0xff) as u8, ((c >> 8) & 0xff) as u8, (c >> 16) as u8]
}

fn armor(block: &[u8], name: &str, comment: Option<&str>) -> String {
    let b = B64.encode(block);
    let lines: Vec<&str> = b.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!(
        "-----BEGIN {name}-----\r\n{}\r\n\r\n{}\r\n={}\r\n-----END {name}-----",
        comment.map(|c| format!("Comment: {c}")).unwrap_or_default(),
        lines.join("\r\n"),
        B64.encode(armory_crc24(block))
    )
}

/// Armory clearsign block (`ASv1CS`), signed with an uncompressed-key compact signature
/// when `compressed` is false (as Armory did).
pub fn clearsign_block(sk: &SecretKey, compressed: bool, msg: &str, comment: &str) -> String {
    let text = format_text(msg, false);
    let kind = if compressed { CompactKind::P2pkhCompressed } else { CompactKind::P2pkhUncompressed };
    let sig = B64.decode(sign_compact(sk, kind, text.as_bytes())).unwrap();
    format!(
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\r\nComment: {comment}\r\n\r\n{text}\r\n{}",
        armor(&sig, "BITCOIN SIGNATURE", None)
    )
}

fn unarmor(body: &str) -> Result<Vec<u8>> {
    let (data, crc) = body.split_once("\n=").ok_or(MessageError::Malformed)?;
    let b64: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = B64.decode(b64).map_err(|_| MessageError::Malformed)?;
    let crc = B64.decode(crc.trim()).map_err(|_| MessageError::Malformed)?;
    if crc != armory_crc24(&bytes) {
        return Err(MessageError::Checksum);
    }
    Ok(bytes)
}

/// Parse an Armory signed block: returns `(compact signature base64, signed message bytes)`.
pub fn read_block(input: &str) -> Result<(String, String)> {
    let r = format_text(input, true);
    let begin = r.find("-----BEGIN ").ok_or(MessageError::Malformed)?;
    let rest = &r[begin + 11..];
    let name_end = rest.find("-----").ok_or(MessageError::Malformed)?;
    let name = &rest[..name_end];
    let after = &rest[name_end + 5..];
    match name {
        "BITCOIN SIGNED MESSAGE" => {
            let body = &after[after.find("\r\n\r\n").ok_or(MessageError::Malformed)? + 4..];
            let msg_end = body.find("\r\n-----").ok_or(MessageError::Malformed)?;
            let msg = &body[..msg_end];
            let sig_part = &body[msg_end..];
            let sb = sig_part.find("-----BEGIN BITCOIN SIGNATURE-----").ok_or(MessageError::Malformed)?;
            let sig_body = &sig_part[sb + 33..];
            let sig_body = &sig_body[..sig_body.find("-----END").unwrap_or(sig_body.len())];
            let sig = unarmor(sig_body)?;
            Ok((B64.encode(sig), msg.to_string()))
        }
        "BITCOIN MESSAGE" => {
            let end = after.find("-----END").unwrap_or(after.len());
            let body = &after[..end];
            let data = &body[body.find("\r\n\r\n").ok_or(MessageError::Malformed)? + 4..];
            let bytes = unarmor(data)?;
            if bytes.len() < 65 {
                return Err(MessageError::Malformed);
            }
            Ok((B64.encode(&bytes[..65]), String::from_utf8_lossy(&bytes[65..]).into_owned()))
        }
        other => Err(MessageError::UnknownBlock(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    // pytest/testJasvet.py:79-90 — an Armory clearsign block signed by the announcement key.
    #[test]
    fn armory_093_clearsign_block() {
        let block = include_str!("../tests/data/jasvet_clearsign_block.txt");
        let (sig, msg) = read_block(block).unwrap();
        assert_eq!(
            sig,
            "G/8M14BRD6GU96y6o1x+9xSfoWBdzZp8p1e/vAZ857D4l9+ozM08CTnzqsxkv1GANssNh1MEmtqgrgEfSPRX5gU="
        );
        assert_eq!(recovered_p2pkh(&sig, msg.as_bytes(), 0).unwrap(), "1NWvhByxfTXPYNT4zMBmEY3VL8QJQtQoei");
        let addr = Address::from_str("1NWvhByxfTXPYNT4zMBmEY3VL8QJQtQoei").unwrap().assume_checked();
        verify(&addr, msg.as_bytes(), &sig).unwrap();
        // Tampering breaks it.
        assert!(
            read_block(&block.replace("changelog", "Changelog"))
                .map(|(s, m)| verify(&addr, m.as_bytes(), &s))
                .unwrap()
                .is_err()
        );
    }

    // testJasvet.py:64-67
    #[test]
    fn format_msg_vector() {
        let mut data = b"\x18Bitcoin Signed Message:\n".to_vec();
        data.push(5);
        data.extend_from_slice(b"hello");
        assert_eq!(hex(&data), "18426974636f696e205369676e6564204d6573736167653a0a0568656c6c6f");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn clearsign_roundtrip_and_crc() {
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let block = clearsign_block(&sk, false, "Hello\n-dash line\nbye  ", "Signed by Armory (Rust)");
        let (sig, msg) = read_block(&block).unwrap();
        assert!(msg.contains("- -dash line"));
        let pk = sk.public_key(&Secp256k1::new()).serialize_uncompressed();
        let mut p = vec![0u8];
        p.extend_from_slice(&armory_crypto::hash::hash160(&pk));
        assert_eq!(
            recovered_p2pkh(&sig, msg.as_bytes(), 0).unwrap(),
            armory_crypto::base58::encode_check(&p)
        );
    }

    // BIP322 test vectors.
    #[test]
    fn bip322_vectors() {
        assert_eq!(
            hex(&bip322_msg_hash(b"")),
            "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"
        );
        assert_eq!(
            hex(&bip322_msg_hash(b"Hello World")),
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"
        );
        let addr = Address::from_str("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l").unwrap().assume_checked();
        verify(
            &addr,
            b"Hello World",
            "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
        )
        .unwrap();
        verify(
            &addr,
            b"",
            "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
        )
        .unwrap();
        assert!(verify(&addr, b"Hello World!", "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=").is_err());
        // Our RFC 6979 signer reproduces BIP322's second published "Hello World" signature.
        let sk = bitcoin::PrivateKey::from_wif("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k")
            .unwrap()
            .inner;
        assert_eq!(
            sign_bip322(&sk, &addr, b"Hello World").unwrap(),
            "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
        );
    }

    #[test]
    fn taproot_and_compact_roundtrips() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let (x, _) = sk.public_key(&secp).x_only_public_key();
        let tr = Address::p2tr(&secp, x, None, bitcoin::Network::Bitcoin);
        let s = sign_bip322(&sk, &tr, b"taproot").unwrap();
        verify(&tr, b"taproot", &s).unwrap();
        assert!(verify(&tr, b"other", &s).is_err());
        let wpkh = Address::p2wpkh(&CompressedPublicKey(sk.public_key(&secp)), bitcoin::Network::Bitcoin);
        let c = sign_compact(&sk, CompactKind::P2wpkh, b"segwit");
        verify(&wpkh, b"segwit", &c).unwrap();
        let p2pkh_u = Address::p2pkh(
            PubkeyHash::hash(&sk.public_key(&secp).serialize_uncompressed()),
            bitcoin::Network::Bitcoin,
        );
        let cu = sign_compact(&sk, CompactKind::P2pkhUncompressed, b"legacy");
        verify(&p2pkh_u, b"legacy", &cu).unwrap();
        assert!(verify(&wpkh, b"legacy", &cu).is_err());
    }
}
