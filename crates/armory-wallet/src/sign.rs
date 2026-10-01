//! PSBT signing and finalization for modern wallets: BIP84 (P2WPKH), BIP86 (P2TR key path) and
//! migrated legacy-1.35 accounts (P2PKH with uncompressed keys). Works offline.

use std::collections::BTreeMap;

use bitcoin::bip32::{DerivationPath, Fingerprint, KeySource};
use bitcoin::key::{PrivateKey, Secp256k1};
use bitcoin::psbt::{GetKey, GetKeyError, KeyRequest, Psbt};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{self, Signing};
use bitcoin::{Address, Network, ScriptBuf, TxOut, Witness};

use crate::modern::{AccountKind, ModernError, ModernWallet, Result, Unlocked};

/// Keys an unlocked wallet can sign with.
pub struct WalletKeys {
    master: bitcoin::bip32::Xpriv,
    /// Legacy P2PKH keys (uncompressed) and imported legacy keys, by public key.
    legacy: BTreeMap<secp256k1::PublicKey, PrivateKey>,
}

impl GetKey for WalletKeys {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        req: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> std::result::Result<Option<PrivateKey>, Self::Error> {
        match req {
            KeyRequest::Bip32(src) => {
                // Legacy inputs carry a placeholder origin; they are answered by public key.
                if src.0 == self.master.fingerprint(secp) {
                    self.master.get_key(KeyRequest::Bip32(src), secp)
                } else {
                    Ok(None)
                }
            }
            KeyRequest::Pubkey(pk) => Ok(self.legacy.get(&pk.inner).copied()),
            _ => Ok(None),
        }
    }
}

/// Key source used to mark legacy inputs in a PSBT: no BIP32 origin.
fn legacy_source() -> KeySource {
    (Fingerprint::default(), DerivationPath::master())
}

fn prevout(psbt: &Psbt, i: usize) -> Option<TxOut> {
    let inp = &psbt.inputs[i];
    if let Some(u) = &inp.witness_utxo {
        return Some(u.clone());
    }
    let op = psbt.unsigned_tx.input[i].previous_output;
    inp.non_witness_utxo.as_ref().and_then(|t| t.output.get(op.vout as usize).cloned())
}

/// Summary of a PSBT for review before signing or broadcasting.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PsbtSummary {
    pub txid: String,
    pub inputs: usize,
    pub input_total: Option<u64>,
    pub outputs: Vec<(String, u64, bool)>,
    pub fee: Option<u64>,
    pub vsize_estimate: usize,
    pub signed_inputs: usize,
    /// Per input: "complete", "unsigned" or "k of m" for multisig.
    pub signature_status: Vec<String>,
    pub rbf: bool,
}

impl ModernWallet {
    /// Collect the signing keys: the seed, and legacy-account keys for every handed-out address
    /// plus `legacy_gap` more (the same range the backend watches).
    pub fn signing_keys(&self, unlocked: &Unlocked, legacy_gap: u32) -> Result<WalletKeys> {
        let secp = Secp256k1::new();
        let mut legacy = BTreeMap::new();
        let net = self.network;
        for (i, a) in self.accounts.iter().enumerate() {
            if a.kind != AccountKind::Legacy135 {
                continue;
            }
            for idx in 0..a.next_receive + legacy_gap {
                let k = self.legacy_private_key(unlocked, i, idx)?;
                let sk = secp256k1::SecretKey::from_slice(&k[..])
                    .map_err(|e| ModernError::Invalid(e.to_string()))?;
                legacy.insert(
                    sk.public_key(&secp),
                    PrivateKey { compressed: false, network: net.into(), inner: sk },
                );
            }
        }
        for k in unlocked.secrets.imported_keys.values() {
            let b = hex_decode(k)?;
            let sk = secp256k1::SecretKey::from_slice(&b).map_err(|e| ModernError::Invalid(e.to_string()))?;
            legacy.insert(
                sk.public_key(&secp),
                PrivateKey { compressed: false, network: net.into(), inner: sk },
            );
        }
        Ok(WalletKeys { master: *unlocked.master(), legacy })
    }

    /// Add key information for legacy P2PKH inputs (Core cannot, as they have no BIP32 origin).
    pub fn annotate_legacy_inputs(&self, psbt: &mut Psbt, keys: &WalletKeys) {
        for i in 0..psbt.inputs.len() {
            let Some(out) = prevout(psbt, i) else { continue };
            let ms_keys: Vec<Vec<u8>> = psbt.inputs[i]
                .witness_script
                .as_ref()
                .or(psbt.inputs[i].redeem_script.as_ref())
                .and_then(|s| crate::lockbox::script_keys(s.as_bytes()).ok())
                .map(|(_, k)| k)
                .unwrap_or_default();
            for pk in keys.legacy.keys() {
                let bpk = bitcoin::PublicKey { compressed: false, inner: *pk };
                if out.script_pubkey == ScriptBuf::new_p2pkh(&bpk.pubkey_hash())
                    || ms_keys.iter().any(|k| k[..] == pk.serialize_uncompressed()[..])
                {
                    psbt.inputs[i].bip32_derivation.insert(*pk, legacy_source());
                }
            }
        }
    }

    /// Sign every input this wallet owns. Returns the number of inputs signed.
    pub fn sign_psbt(&self, unlocked: &Unlocked, psbt: &mut Psbt, legacy_gap: u32) -> Result<usize> {
        let keys = self.signing_keys(unlocked, legacy_gap)?;
        self.annotate_legacy_inputs(psbt, &keys);
        let secp = Secp256k1::new();
        let used = match psbt.sign(&keys, &secp) {
            Ok(u) => u,
            Err((_, errors)) => {
                return Err(ModernError::Invalid(format!("signing failed: {errors:?}")));
            }
        };
        Ok(used
            .values()
            .filter(|v| !matches!(v, bitcoin::psbt::SigningKeys::Ecdsa(k) if k.is_empty()))
            .count())
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| ModernError::Invalid(e.to_string()))
        })
        .collect()
}

/// Check a cosigner's signature on multisig input `i` (P2WSH or P2SH) against its sighash.
fn multisig_sig_valid(
    tx: &bitcoin::Transaction,
    i: usize,
    segwit: bool,
    script: &ScriptBuf,
    amount: bitcoin::Amount,
    pk: &bitcoin::PublicKey,
    sig: &bitcoin::ecdsa::Signature,
) -> bool {
    use bitcoin::hashes::Hash;
    let mut cache = bitcoin::sighash::SighashCache::new(tx);
    let digest = if segwit {
        cache.p2wsh_signature_hash(i, script, amount, sig.sighash_type).ok().map(|h| h.to_byte_array())
    } else {
        cache.legacy_signature_hash(i, script, sig.sighash_type.to_u32()).ok().map(|h| h.to_byte_array())
    };
    let Some(digest) = digest else { return false };
    Secp256k1::verification_only()
        .verify_ecdsa(&secp256k1::Message::from_digest(digest), &sig.signature, &pk.inner)
        .is_ok()
}

/// Finalize P2WPKH, P2PKH and P2TR key-path inputs that carry their signatures, and multisig
/// (P2WSH / P2SH) inputs once enough cosigners signed. Every multisig signature is verified first:
/// a bad signature from a cosigner is reported, never broadcast.
/// Returns an error naming the first input that cannot be finalized.
pub fn finalize(psbt: &mut Psbt) -> Result<()> {
    let tx = psbt.unsigned_tx.clone();
    for i in 0..psbt.inputs.len() {
        let out = prevout(psbt, i)
            .ok_or_else(|| ModernError::Invalid(format!("input {i}: previous output unknown")))?;
        let inp = &mut psbt.inputs[i];
        if inp.final_script_sig.is_some() || inp.final_script_witness.is_some() {
            continue;
        }
        let spk = &out.script_pubkey;
        let ms_script = if spk.is_p2wsh() {
            inp.witness_script.clone()
        } else if spk.is_p2sh() {
            inp.redeem_script.clone().filter(|r| crate::lockbox::script_keys(r.as_bytes()).is_ok())
        } else {
            None
        };
        if let Some(script) = ms_script {
            let (m, keys) = crate::lockbox::script_keys(script.as_bytes())?;
            let mut sigs = Vec::new();
            for k in &keys {
                if let Ok(pk) = bitcoin::PublicKey::from_slice(k) {
                    if let Some(sig) = inp.partial_sigs.get(&pk) {
                        if !multisig_sig_valid(&tx, i, spk.is_p2wsh(), &script, out.value, &pk, sig) {
                            return Err(ModernError::Invalid(format!(
                                "input {i}: the signature of key {pk} is invalid"
                            )));
                        }
                        sigs.push(sig.to_vec());
                    }
                }
            }
            if sigs.len() < usize::from(m) {
                return Err(ModernError::Invalid(format!("input {i}: {} of {m} signatures", sigs.len())));
            }
            sigs.truncate(usize::from(m));
            if spk.is_p2wsh() {
                let mut items: Vec<Vec<u8>> = vec![vec![]];
                items.extend(sigs);
                items.push(script.to_bytes());
                inp.final_script_witness = Some(Witness::from_slice(&items));
            } else {
                let mut b = Builder::new().push_opcode(bitcoin::opcodes::OP_0);
                for sg in sigs {
                    b = b.push_slice(
                        PushBytesBuf::try_from(sg).map_err(|e| ModernError::Invalid(e.to_string()))?,
                    );
                }
                let rs = PushBytesBuf::try_from(script.to_bytes())
                    .map_err(|e| ModernError::Invalid(e.to_string()))?;
                inp.final_script_sig = Some(b.push_slice(rs).into_script());
            }
        } else if spk.is_p2tr() {
            let sig =
                inp.tap_key_sig.ok_or_else(|| ModernError::Invalid(format!("input {i}: not signed")))?;
            inp.final_script_witness = Some(Witness::from_slice(&[sig.to_vec()]));
        } else if spk.is_p2wpkh() || spk.is_p2pkh() {
            let (pk, sig) = inp
                .partial_sigs
                .iter()
                .find(|(pk, _)| {
                    if spk.is_p2wpkh() {
                        pk.wpubkey_hash().is_ok_and(|h| *spk == ScriptBuf::new_p2wpkh(&h))
                    } else {
                        *spk == ScriptBuf::new_p2pkh(&pk.pubkey_hash())
                    }
                })
                .map(|(pk, s)| (*pk, *s))
                .ok_or_else(|| ModernError::Invalid(format!("input {i}: not signed")))?;
            if spk.is_p2wpkh() {
                inp.final_script_witness = Some(Witness::from_slice(&[sig.to_vec(), pk.to_bytes()]));
            } else {
                let s =
                    PushBytesBuf::try_from(sig.to_vec()).map_err(|e| ModernError::Invalid(e.to_string()))?;
                let p =
                    PushBytesBuf::try_from(pk.to_bytes()).map_err(|e| ModernError::Invalid(e.to_string()))?;
                inp.final_script_sig = Some(Builder::new().push_slice(s).push_slice(p).into_script());
            }
        } else {
            return Err(ModernError::Invalid(format!("input {i}: unsupported script type")));
        }
        inp.partial_sigs.clear();
        inp.bip32_derivation.clear();
        inp.tap_key_sig = None;
        inp.tap_key_origins.clear();
        inp.tap_internal_key = None;
        inp.sighash_type = None;
        inp.redeem_script = None;
        inp.witness_script = None;
    }
    Ok(())
}

/// What a PSBT built by the backend must do, checked before signing.
#[derive(Debug, Clone)]
pub struct Expected {
    /// Payments that must appear exactly (script, satoshis). Empty for a sweep.
    pub payments: Vec<(ScriptBuf, u64)>,
    /// For send-max and sweeps: the single destination, which receives everything minus the fee.
    pub sweep_to: Option<ScriptBuf>,
    /// Upper bound on the fee in satoshis.
    pub max_fee: u64,
}

/// Refuse a PSBT that does not match the request: foreign inputs, missing or altered payments,
/// outputs to anyone but the requested recipients and this wallet, or an excessive fee. This
/// protects `--yes` and scripted use against a misbehaving node.
pub fn check_psbt(psbt: &Psbt, own: &dyn Fn(&ScriptBuf) -> bool, expected: &Expected) -> Result<()> {
    let bad = |m: String| Err(ModernError::Invalid(format!("refusing to sign: {m}")));
    let mut input_total = 0u64;
    for i in 0..psbt.inputs.len() {
        let Some(out) = prevout(psbt, i) else {
            return bad(format!("input {i} has no previous output data"));
        };
        if !own(&out.script_pubkey) {
            return bad(format!("input {i} does not belong to this wallet"));
        }
        input_total += out.value.to_sat();
    }
    let mut unmatched: Vec<(ScriptBuf, u64)> = expected.payments.clone();
    let mut sweep_amount = None;
    for o in &psbt.unsigned_tx.output {
        let v = o.value.to_sat();
        if let Some(pos) = unmatched.iter().position(|(s, a)| *s == o.script_pubkey && *a == v) {
            unmatched.remove(pos);
        } else if expected.sweep_to.as_ref() == Some(&o.script_pubkey) && sweep_amount.is_none() {
            sweep_amount = Some(v);
        } else if !own(&o.script_pubkey) {
            return bad(format!("output to {} was not requested", o.script_pubkey.to_hex_string()));
        }
    }
    if !unmatched.is_empty() {
        return bad(format!("{} requested payment(s) missing or changed", unmatched.len()));
    }
    let out_total: u64 = psbt.unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = input_total
        .checked_sub(out_total)
        .ok_or_else(|| ModernError::Invalid("outputs exceed inputs".into()))?;
    if fee > expected.max_fee {
        return bad(format!("fee {fee} sat exceeds the limit of {} sat", expected.max_fee));
    }
    if expected.sweep_to.is_some() && sweep_amount.is_none() {
        return bad("the destination output is missing".into());
    }
    Ok(())
}

/// Human/JSON summary of a PSBT.
pub fn summarize(psbt: &Psbt, network: Network, mine: &dyn Fn(&ScriptBuf) -> bool) -> PsbtSummary {
    let mut total = Some(0u64);
    for i in 0..psbt.inputs.len() {
        total = match (total, prevout(psbt, i)) {
            (Some(t), Some(o)) => Some(t + o.value.to_sat()),
            _ => None,
        };
    }
    let outputs: Vec<(String, u64, bool)> = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| {
            let a = Address::from_script(&o.script_pubkey, network)
                .map(|a| a.to_string())
                .unwrap_or_else(|_| o.script_pubkey.to_hex_string());
            (a, o.value.to_sat(), mine(&o.script_pubkey))
        })
        .collect();
    let out_total: u64 = outputs.iter().map(|o| o.1).sum();
    let signed = psbt
        .inputs
        .iter()
        .filter(|i| {
            !i.partial_sigs.is_empty()
                || i.tap_key_sig.is_some()
                || i.final_script_sig.is_some()
                || i.final_script_witness.is_some()
        })
        .count();
    let status: Vec<String> = psbt
        .inputs
        .iter()
        .map(|i| {
            if i.final_script_sig.is_some() || i.final_script_witness.is_some() {
                return "complete".to_string();
            }
            let ms = i
                .witness_script
                .as_ref()
                .or(i.redeem_script.as_ref())
                .and_then(|s| crate::lockbox::script_keys(s.as_bytes()).ok());
            match ms {
                Some((m, _)) => {
                    let have = i.partial_sigs.len().min(usize::from(m));
                    if have >= usize::from(m) { "complete".into() } else { format!("{have} of {m}") }
                }
                None if !i.partial_sigs.is_empty() || i.tap_key_sig.is_some() => "complete".into(),
                None => "unsigned".into(),
            }
        })
        .collect();
    // Rough virtual size: 68 vB per P2WPKH input, 58 per P2TR, 180 per P2PKH (uncompressed key);
    // multisig from its script.
    let mut vsize = 11 + psbt.unsigned_tx.output.iter().map(|o| 9 + o.script_pubkey.len()).sum::<usize>();
    for i in 0..psbt.inputs.len() {
        let ms = psbt.inputs[i]
            .witness_script
            .as_ref()
            .map(|s| (s, true))
            .or(psbt.inputs[i].redeem_script.as_ref().map(|s| (s, false)))
            .and_then(|(s, w)| {
                crate::lockbox::script_keys(s.as_bytes()).ok().map(|(m, _)| (s.len(), usize::from(m), w))
            });
        vsize += match prevout(psbt, i).map(|o| o.script_pubkey) {
            _ if ms.is_some() => {
                let (len, m, witness) = ms.unwrap();
                let data = 1 + m * 73 + len + 3;
                if witness { 41 + data.div_ceil(4) } else { 41 + data }
            }
            Some(s) if s.is_p2tr() => 58,
            Some(s) if s.is_p2pkh() => 180,
            _ => 68,
        };
    }
    PsbtSummary {
        txid: psbt.unsigned_tx.compute_txid().to_string(),
        inputs: psbt.inputs.len(),
        input_total: total,
        fee: total.map(|t| t.saturating_sub(out_total)),
        outputs,
        vsize_estimate: vsize,
        signed_inputs: signed,
        signature_status: status,
        rbf: psbt.unsigned_tx.input.iter().any(|i| i.sequence.is_rbf()),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache};
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, Txid, absolute, transaction};

    use super::*;

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// A funding transaction paying to a BIP84, a BIP86 and a migrated legacy address, then a
    /// PSBT spending all three as Core would build it; sign, finalize, verify every signature.
    #[test]
    fn sign_and_finalize_all_script_types() {
        let secp = Secp256k1::new();
        let mut w = ModernWallet::restore(Network::Testnet, "t", ABANDON, "", None, 0).unwrap().wallet;
        let mut u = w.unlock(None).unwrap();
        let tr = w.add_account(&u, AccountKind::Bip86, 0).unwrap();
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/legacy/armory_DZMmtb2v_.wallet");
        let old = crate::LegacyWallet::parse(&std::fs::read(p).unwrap()).unwrap();
        let leg = w.migrate_legacy(&mut u, &old, None, None).unwrap();

        let a84 = w.address(0, 0, 0).unwrap();
        let a86 = w.address(tr, 0, 0).unwrap();
        // A lookahead address past the handed-out ones (next_receive is 4 for this fixture).
        let aleg = w.address(leg, 0, w.accounts[leg].next_receive + 3).unwrap();
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint::new(Txid::all_zeros(), 0), ..Default::default() }],
            output: [&a84, &a86, &aleg]
                .iter()
                .map(|a| TxOut { value: Amount::from_sat(100_000), script_pubkey: a.script_pubkey() })
                .collect(),
        };
        let fid = funding.compute_txid();
        let spend = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: (0..3)
                .map(|v| TxIn {
                    previous_output: OutPoint::new(fid, v),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(290_000),
                script_pubkey: w.address(0, 1, 0).unwrap().script_pubkey(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
        let fp = w.master_fingerprint().unwrap();
        // Input 0: P2WPKH with BIP32 origin (as Core fills it in).
        let p84 = DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap();
        let k84 = u.master().derive_priv(&secp, &p84).unwrap().private_key.public_key(&secp);
        psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
        psbt.inputs[0].bip32_derivation.insert(k84, (fp, p84));
        // Input 1: P2TR key path with tap key origin.
        let p86 = DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();
        let x86 = u.master().derive_priv(&secp, &p86).unwrap().private_key.x_only_public_key(&secp).0;
        psbt.inputs[1].witness_utxo = Some(funding.output[1].clone());
        psbt.inputs[1].tap_internal_key = Some(x86);
        psbt.inputs[1].tap_key_origins.insert(x86, (vec![], (fp, p86)));
        // Input 2: legacy P2PKH, previous transaction only.
        psbt.inputs[2].non_witness_utxo = Some(funding.clone());

        let own_scripts: Vec<ScriptBuf> = [&a84, &a86, &aleg]
            .iter()
            .map(|a| a.script_pubkey())
            .chain([w.address(0, 1, 0).unwrap().script_pubkey()])
            .collect();
        let own = |s: &ScriptBuf| own_scripts.contains(s);
        // As requested: everything to our own change, fee 10_000 sat.
        let ok = Expected { payments: vec![], sweep_to: None, max_fee: 20_000 };
        check_psbt(&psbt, &own, &ok).unwrap();
        // A payment the user asked for that is missing is refused, as is a low fee limit.
        let dest = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros());
        assert!(
            check_psbt(&psbt, &own, &Expected { payments: vec![(dest.clone(), 5)], ..ok.clone() }).is_err()
        );
        assert!(check_psbt(&psbt, &own, &Expected { max_fee: 9_999, ..ok.clone() }).is_err());
        // An output to someone else is refused.
        let mut evil = psbt.clone();
        evil.unsigned_tx.output[0].script_pubkey = dest;
        evil.outputs[0] = Default::default();
        assert!(check_psbt(&evil, &own, &ok).is_err());

        assert_eq!(w.sign_psbt(&u, &mut psbt, 5).unwrap(), 3);
        let summary = summarize(&psbt, Network::Testnet, &|_| false);
        assert_eq!((summary.signed_inputs, summary.fee), (3, Some(10_000)));
        assert!(summary.rbf);
        finalize(&mut psbt).unwrap();
        let tx = psbt.extract_tx().unwrap();

        // Verify each signature against the sighash.
        let prevouts: Vec<TxOut> = funding.output.clone();
        let mut cache = SighashCache::new(&tx);
        let w0 = &tx.input[0].witness;
        let sig = bitcoin::ecdsa::Signature::from_slice(&w0.to_vec()[0]).unwrap();
        let pk = bitcoin::PublicKey::from_slice(&w0.to_vec()[1]).unwrap();
        let h = cache
            .p2wpkh_signature_hash(0, &prevouts[0].script_pubkey, prevouts[0].value, sig.sighash_type)
            .unwrap();
        secp.verify_ecdsa(&secp256k1::Message::from_digest(h.to_byte_array()), &sig.signature, &pk.inner)
            .unwrap();

        let tsig = bitcoin::taproot::Signature::from_slice(&tx.input[1].witness.to_vec()[0]).unwrap();
        let th =
            cache.taproot_key_spend_signature_hash(1, &Prevouts::All(&prevouts), tsig.sighash_type).unwrap();
        let out_key =
            bitcoin::key::XOnlyPublicKey::from_slice(&prevouts[1].script_pubkey.as_bytes()[2..]).unwrap();
        secp.verify_schnorr(&tsig.signature, &secp256k1::Message::from_digest(th.to_byte_array()), &out_key)
            .unwrap();

        let ss: Vec<Vec<u8>> = tx.input[2]
            .script_sig
            .instructions()
            .map(|i| i.unwrap().push_bytes().unwrap().as_bytes().to_vec())
            .collect();
        assert_eq!(ss[1].len(), 65, "legacy keys are uncompressed");
        let lsig = bitcoin::ecdsa::Signature::from_slice(&ss[0]).unwrap();
        let lh =
            cache.legacy_signature_hash(2, &prevouts[2].script_pubkey, lsig.sighash_type.to_u32()).unwrap();
        let lpk = bitcoin::PublicKey::from_slice(&ss[1]).unwrap();
        secp.verify_ecdsa(&secp256k1::Message::from_digest(lh.to_byte_array()), &lsig.signature, &lpk.inner)
            .unwrap();
    }

    #[test]
    fn unsigned_input_cannot_finalize() {
        let w = ModernWallet::restore(Network::Testnet, "t", ABANDON, "", None, 0).unwrap().wallet;
        let a = w.address(0, 0, 0).unwrap();
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut { value: Amount::from_sat(1), script_pubkey: a.script_pubkey() }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo =
            Some(TxOut { value: Amount::from_sat(2), script_pubkey: a.script_pubkey() });
        assert!(finalize(&mut psbt).is_err());
    }
}
