//! Armory 0.93 offline-signing files (`TXSIGCOLLECT` blocks, "USTX"; spec 03 §1).
//!
//! All three layouts seen in the wild (all labelled version 1) are read, recognised by full
//! consumption, outpoint-hash and ID checks. A USTX converts to a PSBT (carrying the previous
//! transactions, redeem scripts and any signatures, normalised to low-S) so the rest of the
//! program can show, sign, combine and broadcast it; a PSBT with legacy inputs converts back to a
//! USTX block for an Armory 0.93 offline signer.

use base64::Engine;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction,
};

use crate::lockbox::parse_armored;
use crate::modern::{ModernError, Result, legacy_network};

fn invalid(e: impl std::fmt::Display) -> ModernError {
    ModernError::Invalid(e.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UstxInput {
    pub outpoint: OutPoint,
    pub support_tx: Transaction,
    pub p2sh_script: Vec<u8>,
    pub contrib_id: String,
    pub contrib_label: String,
    pub sequence: u32,
    /// `(public key, signature with hashtype byte or empty)`.
    pub keys: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UstxOutput {
    pub script: Vec<u8>,
    pub value: u64,
    pub p2sh_script: Vec<u8>,
    pub contrib_id: String,
    pub contrib_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ustx {
    pub id: String,
    pub lock_time: u32,
    pub inputs: Vec<UstxInput>,
    pub outputs: Vec<UstxOutput>,
    /// 0, 1 or 2 (see spec 03 §1.9).
    pub generation: u8,
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.b.get(self.p..self.p + n).ok_or_else(|| invalid("truncated"))?;
        self.p += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn varint(&mut self) -> Result<u64> {
        Ok(match self.take(1)?[0] {
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
    fn done(&self) -> bool {
        self.p == self.b.len()
    }
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn parse_input(data: &[u8], magic: [u8; 4], layout: u8) -> Result<UstxInput> {
    let mut r = R { b: data, p: 0 };
    r.u32()?;
    if r.take(4)? != magic {
        return Err(invalid("wrong network"));
    }
    let op = r.take(36)?;
    let support: Transaction = deserialize(r.varstr()?).map_err(invalid)?;
    let outpoint =
        OutPoint { txid: support.compute_txid(), vout: u32::from_le_bytes(op[32..].try_into().unwrap()) };
    if op[..32] != serialize(&support.compute_txid())[..] {
        return Err(invalid("outpoint does not match the supporting transaction"));
    }
    let p2sh_script = r.varstr()?.to_vec();
    let contrib_id = s(r.varstr()?);
    let contrib_label = if layout >= 2 { s(r.varstr()?) } else { String::new() };
    let sequence = r.u32()?;
    let n = r.varint()?;
    let mut keys = Vec::new();
    for _ in 0..n {
        let pk = r.varstr()?.to_vec();
        let sig = r.varstr()?.to_vec();
        r.varstr()?; // wallet locator
        keys.push((pk, sig));
    }
    if !r.done() {
        return Err(invalid("trailing bytes"));
    }
    Ok(UstxInput { outpoint, support_tx: support, p2sh_script, contrib_id, contrib_label, sequence, keys })
}

fn parse_output(data: &[u8], magic: [u8; 4], layout: u8) -> Result<UstxOutput> {
    let mut r = R { b: data, p: 0 };
    r.u32()?;
    if r.take(4)? != magic {
        return Err(invalid("wrong network"));
    }
    let script = r.varstr()?.to_vec();
    let value = r.u64()?;
    let p2sh_script = r.varstr()?.to_vec();
    r.varstr()?; // locator
    r.varstr()?; // auth method
    r.varstr()?; // auth data
    let (contrib_id, contrib_label) = match layout {
        2 => (s(r.varstr()?), s(r.varstr()?)),
        1 => (s(r.varstr()?), String::new()),
        _ => (String::new(), String::new()),
    };
    if !r.done() {
        return Err(invalid("trailing bytes"));
    }
    Ok(UstxOutput { script, value, p2sh_script, contrib_id, contrib_label })
}

impl Ustx {
    /// The unsigned transaction Armory signs (version 1, empty input scripts).
    pub fn unsigned_tx(&self) -> Transaction {
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::from_consensus(self.lock_time),
            input: self
                .inputs
                .iter()
                .map(|i| TxIn {
                    previous_output: i.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(i.sequence),
                    witness: Witness::new(),
                })
                .collect(),
            output: self
                .outputs
                .iter()
                .map(|o| TxOut {
                    value: Amount::from_sat(o.value),
                    script_pubkey: ScriptBuf::from_bytes(o.script.clone()),
                })
                .collect(),
        }
    }

    pub fn compute_id(&self) -> String {
        let h = armory_crypto::hash::hash256(&serialize(&self.unsigned_tx()));
        armory_crypto::base58::encode(&h).chars().take(8).collect()
    }

    fn parse_body(
        data: &[u8],
        network: Network,
        layout: u8,
    ) -> Result<(u32, Vec<UstxInput>, Vec<UstxOutput>)> {
        let magic = legacy_network(network).magic();
        let mut r = R { b: data, p: 0 };
        r.u32()?;
        if r.take(4)? != magic {
            return Err(invalid("the transaction file is for another network"));
        }
        let lock_time = r.u32()?;
        let nin = r.varint()?;
        let mut ins = Vec::new();
        for _ in 0..nin {
            ins.push(parse_input(r.varstr()?, magic, layout)?);
        }
        let nout = r.varint()?;
        let mut outs = Vec::new();
        for _ in 0..nout {
            outs.push(parse_output(r.varstr()?, magic, layout)?);
        }
        if !r.done() {
            return Err(invalid("trailing bytes"));
        }
        Ok((lock_time, ins, outs))
    }

    /// Parse the first `TXSIGCOLLECT` block in `text`.
    pub fn parse(text: &str, network: Network) -> Result<Self> {
        let block = parse_armored(text)?
            .into_iter()
            .find(|b| b.kind == "TXSIGCOLLECT")
            .ok_or_else(|| invalid("no TXSIGCOLLECT block found"))?;
        let mut last = invalid("unreadable transaction file");
        for layout in [2u8, 1, 0] {
            match Self::parse_body(&block.data, network, layout) {
                Ok((lock_time, inputs, outputs)) => {
                    let u = Ustx { id: block.id.clone(), lock_time, inputs, outputs, generation: layout };
                    let id = u.compute_id();
                    if id != block.id {
                        return Err(invalid(format!(
                            "ID mismatch: block says {}, contents give {id}",
                            block.id
                        )));
                    }
                    return Ok(u);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Convert to a PSBT. Signatures are normalised to low-S (as Armory did when finalizing).
    pub fn to_psbt(&self) -> Result<Psbt> {
        let mut psbt = Psbt::from_unsigned_tx(self.unsigned_tx()).map_err(invalid)?;
        for (i, inp) in self.inputs.iter().enumerate() {
            psbt.inputs[i].non_witness_utxo = Some(inp.support_tx.clone());
            if !inp.p2sh_script.is_empty() {
                psbt.inputs[i].redeem_script = Some(ScriptBuf::from_bytes(inp.p2sh_script.clone()));
            }
            for (pk, sig) in &inp.keys {
                if sig.is_empty() {
                    continue;
                }
                let pk = bitcoin::PublicKey::from_slice(pk).map_err(invalid)?;
                let (der, ht) = sig.split_at(sig.len() - 1);
                let mut s = bitcoin::secp256k1::ecdsa::Signature::from_der_lax(der).map_err(invalid)?;
                s.normalize_s();
                let sighash_type =
                    bitcoin::sighash::EcdsaSighashType::from_standard(u32::from(ht[0])).map_err(invalid)?;
                psbt.inputs[i]
                    .partial_sigs
                    .insert(pk, bitcoin::ecdsa::Signature { signature: s, sighash_type });
            }
        }
        Ok(psbt)
    }

    /// Build a USTX (layout 2) from a PSBT whose inputs are legacy (non-SegWit) and carry their
    /// previous transactions, so an Armory 0.93 offline machine can sign it.
    pub fn from_psbt(psbt: &Psbt) -> Result<Self> {
        let mut inputs = Vec::new();
        for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
            let pi = &psbt.inputs[i];
            let support = pi
                .non_witness_utxo
                .clone()
                .ok_or_else(|| invalid(format!("input {i}: Armory 0.93 needs the previous transaction")))?;
            let spk = &support
                .output
                .get(txin.previous_output.vout as usize)
                .ok_or_else(|| invalid("bad outpoint"))?
                .script_pubkey;
            if spk.is_witness_program() {
                return Err(invalid(format!("input {i} is SegWit; Armory 0.93 cannot sign it")));
            }
            let mut keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            if let Some(rs) = &pi.redeem_script {
                let (_, ks) = crate::lockbox::script_keys(rs.as_bytes())?;
                for k in ks {
                    let sig = bitcoin::PublicKey::from_slice(&k)
                        .ok()
                        .and_then(|p| pi.partial_sigs.get(&p))
                        .map(|s| s.to_vec())
                        .unwrap_or_default();
                    keys.push((k, sig));
                }
            } else {
                // The key whose hash the output pays to (Armory keys are uncompressed).
                let candidates: Vec<Vec<u8>> = pi
                    .bip32_derivation
                    .keys()
                    .flat_map(|k| [k.serialize_uncompressed().to_vec(), k.serialize().to_vec()])
                    .chain(pi.partial_sigs.keys().map(|k| k.to_bytes()))
                    .collect();
                let pk = candidates
                    .into_iter()
                    .find(|k| *spk == ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::hash(k)))
                    .ok_or_else(|| invalid(format!("input {i}: public key unknown")))?;
                let sig = pi.partial_sigs.values().next().map(|s| s.to_vec()).unwrap_or_default();
                keys.push((pk, sig));
            }
            inputs.push(UstxInput {
                outpoint: txin.previous_output,
                support_tx: support,
                p2sh_script: pi.redeem_script.as_ref().map(|s| s.to_bytes()).unwrap_or_default(),
                contrib_id: String::new(),
                contrib_label: String::new(),
                sequence: txin.sequence.0,
                keys,
            });
        }
        let outputs = psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| UstxOutput {
                script: o.script_pubkey.to_bytes(),
                value: o.value.to_sat(),
                p2sh_script: vec![],
                contrib_id: String::new(),
                contrib_label: String::new(),
            })
            .collect();
        let mut u = Ustx {
            id: String::new(),
            lock_time: psbt.unsigned_tx.lock_time.to_consensus_u32(),
            inputs,
            outputs,
            generation: 2,
        };
        if psbt.unsigned_tx.version != transaction::Version::ONE {
            return Err(invalid("Armory 0.93 only signs version-1 transactions"));
        }
        u.id = u.compute_id();
        Ok(u)
    }

    /// Serialize as a layout-2 `TXSIGCOLLECT` block (64-character lines, as Armory 0.93.3).
    pub fn to_block(&self, network: Network) -> String {
        let magic = legacy_network(network).magic();
        let vs = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend(serialize(&bitcoin::VarInt(b.len() as u64)));
            out.extend_from_slice(b);
        };
        let mut body = 1u32.to_le_bytes().to_vec();
        body.extend_from_slice(&magic);
        body.extend_from_slice(&self.lock_time.to_le_bytes());
        body.extend(serialize(&bitcoin::VarInt(self.inputs.len() as u64)));
        for i in &self.inputs {
            let mut b = 1u32.to_le_bytes().to_vec();
            b.extend_from_slice(&magic);
            b.extend(serialize(&i.outpoint));
            vs(&mut b, &serialize(&i.support_tx));
            vs(&mut b, &i.p2sh_script);
            vs(&mut b, i.contrib_id.as_bytes());
            vs(&mut b, i.contrib_label.as_bytes());
            b.extend_from_slice(&i.sequence.to_le_bytes());
            b.extend(serialize(&bitcoin::VarInt(i.keys.len() as u64)));
            for (pk, sig) in &i.keys {
                vs(&mut b, pk);
                vs(&mut b, sig);
                vs(&mut b, &[]);
            }
            vs(&mut body, &b);
        }
        body.extend(serialize(&bitcoin::VarInt(self.outputs.len() as u64)));
        for o in &self.outputs {
            let mut b = 1u32.to_le_bytes().to_vec();
            b.extend_from_slice(&magic);
            vs(&mut b, &o.script);
            b.extend_from_slice(&o.value.to_le_bytes());
            vs(&mut b, &o.p2sh_script);
            vs(&mut b, &[]);
            vs(&mut b, b"NONE");
            vs(&mut b, &[]);
            vs(&mut b, o.contrib_id.as_bytes());
            vs(&mut b, o.contrib_label.as_bytes());
            vs(&mut body, &b);
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&body);
        let mut out = format!("{:=<64}", format!("=====TXSIGCOLLECT-{}", self.id));
        for chunk in b64.as_bytes().chunks(64) {
            out.push('\n');
            out.push_str(std::str::from_utf8(chunk).unwrap());
        }
        out.push('\n');
        out.push_str(&"=".repeat(64));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy").join(name);
        std::fs::read_to_string(p).unwrap()
    }

    // spec 03 §8.1: the signed fixture finalizes to the documented low-S transaction.
    #[test]
    fn signed_fixture_finalizes() {
        let u = Ustx::parse(&fixture("armory_8gRmZv48_.signed.tx"), Network::Testnet).unwrap();
        assert_eq!((u.id.as_str(), u.generation, u.inputs.len(), u.outputs.len()), ("8gRmZv48", 2, 1, 2));
        let mut psbt = u.to_psbt().unwrap();
        crate::sign::finalize(&mut psbt).unwrap();
        let tx = psbt.extract_tx().unwrap();
        assert_eq!(
            tx.compute_txid().to_string(),
            "347f1b745b3b7fb38bbec2af070f31cc567cedf41693008ae451950d77a3d5d0"
        );
    }

    // spec 03 §8.2-8.3: the other layouts and the unsigned simulfunding file.
    #[test]
    fn other_layouts() {
        let g1 = Ustx::parse(&fixture("armory_Ev9L4wAd_.signed.tx"), Network::Testnet).unwrap();
        assert_eq!((g1.id.as_str(), g1.generation), ("Ev9L4wAd", 1));
        let un = Ustx::parse(&fixture("armory_EyUJNfMQ_.unsigned.tx"), Network::Testnet).unwrap();
        assert_eq!(un.id, "Ev9L4wAd");
        assert!(un.inputs[0].keys.iter().all(|(_, s)| s.is_empty()));
        let sf = Ustx::parse(&fixture("Simulfund_fmuHCs5G.sigcollect.tx"), Network::Testnet).unwrap();
        assert_eq!((sf.id.as_str(), sf.inputs.len(), sf.outputs.len()), ("fmuHCs5G", 3, 4));
        assert_eq!(sf.inputs[0].contrib_label, "ThirdFunder");
        assert!(Ustx::parse(&fixture("armory_8gRmZv48_.signed.tx"), Network::Bitcoin).is_err());
    }

    #[test]
    fn roundtrip_through_psbt() {
        let u = Ustx::parse(&fixture("armory_EyUJNfMQ_.unsigned.tx"), Network::Testnet).unwrap();
        let mut psbt = u.to_psbt().unwrap();
        // The unsigned file carries the key; make it visible like our signer would.
        let pk = bitcoin::PublicKey::from_slice(&u.inputs[0].keys[0].0).unwrap();
        psbt.inputs[0].bip32_derivation.insert(pk.inner, (Default::default(), Default::default()));
        let back = Ustx::from_psbt(&psbt).unwrap();
        assert_eq!(back.id, "Ev9L4wAd");
        let again = Ustx::parse(&back.to_block(Network::Testnet), Network::Testnet).unwrap();
        assert_eq!(again.inputs, back.inputs);
        assert_eq!(again.generation, 2);
    }
}
