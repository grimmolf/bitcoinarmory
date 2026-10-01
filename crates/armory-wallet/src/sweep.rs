//! Sweeping a private key: move every coin the key controls (P2PKH with either key form,
//! P2WPKH, P2SH-P2WPKH, P2TR key path) to one destination, signing each input directly.

use bitcoin::hashes::Hash;
use bitcoin::key::{CompressedPublicKey, Secp256k1, TapTweak};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Address, Amount, Network, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute, transaction,
};

use crate::modern::{ModernError, Result};

fn invalid(e: impl std::fmt::Display) -> ModernError {
    ModernError::Invalid(e.to_string())
}

/// A key to sweep and the scripts it can control.
pub struct SweepKey {
    pub secret: SecretKey,
    pub compressed: bool,
}

impl SweepKey {
    /// Descriptors to search the UTXO set for.
    pub fn descriptors(&self) -> Vec<String> {
        let secp = Secp256k1::new();
        let pk = self.secret.public_key(&secp);
        if self.compressed {
            let h = hex(&pk.serialize());
            let x = hex(&pk.x_only_public_key().0.serialize());
            [format!("pkh({h})"), format!("wpkh({h})"), format!("sh(wpkh({h}))"), format!("tr({x})")]
                .iter()
                .map(|d| crate::descriptor::with_checksum(d))
                .collect()
        } else {
            vec![crate::descriptor::with_checksum(&format!("pkh({})", hex(&pk.serialize_uncompressed())))]
        }
    }

    /// The addresses this key controls (for display).
    pub fn addresses(&self, network: Network) -> Vec<Address> {
        let secp = Secp256k1::new();
        let pk = self.secret.public_key(&secp);
        if !self.compressed {
            return vec![Address::p2pkh(PubkeyHash::hash(&pk.serialize_uncompressed()), network)];
        }
        let cpk = CompressedPublicKey(pk);
        vec![
            Address::p2pkh(cpk.pubkey_hash(), network),
            Address::p2wpkh(&cpk, network),
            Address::p2shwpkh(&cpk, network),
            Address::p2tr(&secp, pk.x_only_public_key().0, None, network),
        ]
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One coin to sweep.
#[derive(Debug, Clone)]
pub struct SweepInput {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: ScriptBuf,
}

fn input_vbytes(spk: &ScriptBuf, compressed: bool) -> usize {
    if spk.is_p2tr() {
        58
    } else if spk.is_p2wpkh() {
        68
    } else if spk.is_p2sh() {
        91
    } else if compressed {
        148
    } else {
        180
    }
}

/// Build and sign the sweep. Fails if the fee would consume the coins.
pub fn sweep(key: &SweepKey, coins: &[SweepInput], dest: &Address, fee_rate: f64) -> Result<Transaction> {
    if coins.is_empty() {
        return Err(invalid("nothing to sweep"));
    }
    let secp = Secp256k1::new();
    let pk = key.secret.public_key(&secp);
    let total: u64 = coins.iter().map(|c| c.value).sum();
    let vsize = 11
        + 9
        + dest.script_pubkey().len()
        + coins.iter().map(|c| input_vbytes(&c.script_pubkey, key.compressed)).sum::<usize>();
    let fee = (fee_rate * vsize as f64).ceil() as u64;
    let value = total
        .checked_sub(fee)
        .filter(|v| *v >= 546)
        .ok_or_else(|| invalid("the coins are worth less than the fee"))?;
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: coins
            .iter()
            .map(|c| TxIn {
                previous_output: c.outpoint,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            })
            .collect(),
        output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: dest.script_pubkey() }],
    };
    let prevouts: Vec<TxOut> = coins
        .iter()
        .map(|c| TxOut { value: Amount::from_sat(c.value), script_pubkey: c.script_pubkey.clone() })
        .collect();
    let cpk = CompressedPublicKey(pk);
    let pk_bytes =
        if key.compressed { pk.serialize().to_vec() } else { pk.serialize_uncompressed().to_vec() };
    let ecdsa = |h: [u8; 32]| -> Vec<u8> {
        let mut s = secp.sign_ecdsa(&Message::from_digest(h), &key.secret).serialize_der().to_vec();
        s.push(EcdsaSighashType::All as u8);
        s
    };
    let push = |b: Vec<u8>| PushBytesBuf::try_from(b).expect("small push");
    let mut script_sigs = Vec::new();
    let mut witnesses = Vec::new();
    {
        let mut cache = SighashCache::new(&tx);
        for (i, c) in coins.iter().enumerate() {
            let spk = &c.script_pubkey;
            let amt = Amount::from_sat(c.value);
            if spk.is_p2tr() {
                let tweaked =
                    bitcoin::key::Keypair::from_secret_key(&secp, &key.secret).tap_tweak(&secp, None);
                let h = cache
                    .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
                    .map_err(invalid)?;
                let sig = secp.sign_schnorr(&Message::from_digest(h.to_byte_array()), &tweaked.to_keypair());
                script_sigs.push(ScriptBuf::new());
                witnesses.push(Witness::from_slice(&[sig.as_ref().to_vec()]));
            } else if spk.is_p2wpkh() || spk.is_p2sh() {
                let inner = ScriptBuf::new_p2wpkh(&cpk.wpubkey_hash());
                if spk.is_p2sh() && *spk != ScriptBuf::new_p2sh(&inner.script_hash()) {
                    return Err(invalid(format!("input {i}: not controlled by this key")));
                }
                let h =
                    cache.p2wpkh_signature_hash(i, &inner, amt, EcdsaSighashType::All).map_err(invalid)?;
                script_sigs.push(if spk.is_p2sh() {
                    Builder::new().push_slice(push(inner.to_bytes())).into_script()
                } else {
                    ScriptBuf::new()
                });
                witnesses.push(Witness::from_slice(&[ecdsa(h.to_byte_array()), pk.serialize().to_vec()]));
            } else if spk.is_p2pkh() {
                let h = cache.legacy_signature_hash(i, spk, EcdsaSighashType::All as u32).map_err(invalid)?;
                script_sigs.push(
                    Builder::new()
                        .push_slice(push(ecdsa(h.to_byte_array())))
                        .push_slice(push(pk_bytes.clone()))
                        .into_script(),
                );
                witnesses.push(Witness::new());
            } else {
                return Err(invalid(format!("input {i}: unsupported script")));
            }
        }
    }
    for (i, inp) in tx.input.iter_mut().enumerate() {
        inp.script_sig = script_sigs[i].clone();
        inp.witness = witnesses[i].clone();
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use bitcoin::Txid;

    use super::*;

    #[test]
    fn sweeps_every_script_type_and_signatures_verify() {
        let secp = Secp256k1::new();
        for compressed in [true, false] {
            let key = SweepKey { secret: SecretKey::from_slice(&[0x33; 32]).unwrap(), compressed };
            let addrs = key.addresses(Network::Regtest);
            assert_eq!(addrs.len(), if compressed { 4 } else { 1 });
            assert_eq!(key.descriptors().len(), addrs.len());
            let coins: Vec<SweepInput> = addrs
                .iter()
                .enumerate()
                .map(|(i, a)| SweepInput {
                    outpoint: OutPoint::new(Txid::all_zeros(), i as u32),
                    value: 50_000,
                    script_pubkey: a.script_pubkey(),
                })
                .collect();
            let dest = addrs[0].clone();
            let tx = sweep(&key, &coins, &dest, 2.0).unwrap();
            let fee = coins.len() as u64 * 50_000 - tx.output[0].value.to_sat();
            assert!(fee > 0 && fee < 2_000, "fee {fee}");
            // Verify the P2PKH input (index 0) signature.
            let parts: Vec<Vec<u8>> = tx.input[0]
                .script_sig
                .instructions()
                .map(|i| i.unwrap().push_bytes().unwrap().as_bytes().to_vec())
                .collect();
            let sig = bitcoin::ecdsa::Signature::from_slice(&parts[0]).unwrap();
            let h = SighashCache::new(&tx).legacy_signature_hash(0, &coins[0].script_pubkey, 1).unwrap();
            let pk = bitcoin::PublicKey::from_slice(&parts[1]).unwrap();
            assert_eq!(pk.compressed, compressed);
            secp.verify_ecdsa(&Message::from_digest(h.to_byte_array()), &sig.signature, &pk.inner).unwrap();
        }
        let key = SweepKey { secret: SecretKey::from_slice(&[0x33; 32]).unwrap(), compressed: true };
        let a = key.addresses(Network::Regtest);
        let tiny =
            [SweepInput { outpoint: OutPoint::null(), value: 300, script_pubkey: a[1].script_pubkey() }];
        assert!(sweep(&key, &tiny, &a[1], 5.0).is_err());
    }
}
