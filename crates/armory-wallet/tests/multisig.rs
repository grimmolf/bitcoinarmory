//! Lockbox spends: modern 2-of-3 SegWit and an Armory 0.93 2-of-2 P2SH lockbox, each signed
//! by separate wallets, combined and finalized, with every signature verified.

use std::path::PathBuf;
use std::str::FromStr;

use armory_wallet::LegacyWallet;
use armory_wallet::lockbox::{Lockbox, cosigner_key, read_legacy_lockboxes};
use armory_wallet::modern::ModernWallet;
use armory_wallet::sign;
use bitcoin::bip32::DerivationPath;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, absolute, transaction};

fn funding_and_spend(to: &bitcoin::Address, change: &bitcoin::Address) -> (Transaction, Transaction) {
    let funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint::new(Txid::all_zeros(), 0), ..Default::default() }],
        output: vec![TxOut { value: Amount::from_sat(200_000), script_pubkey: to.script_pubkey() }],
    };
    let spend = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.compute_txid(), 0),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        }],
        output: vec![TxOut { value: Amount::from_sat(190_000), script_pubkey: change.script_pubkey() }],
    };
    (funding, spend)
}

#[test]
fn modern_2_of_3_lockbox_spend() {
    let secp = Secp256k1::new();
    let ws: Vec<ModernWallet> = (0..3)
        .map(|i| {
            ModernWallet::generate(Network::Regtest, &format!("w{i}"), 12, "", None, None, 0).unwrap().wallet
        })
        .collect();
    let keys: Vec<String> =
        ws.iter().map(|w| cosigner_key(w, &w.unlock(None).unwrap(), 0).unwrap()).collect();
    let mut lb = Lockbox::new_modern(Network::Regtest, "Family", 2, keys.clone(), vec![], 0).unwrap();
    let addr = lb.next_receive().unwrap();
    let change = lb.next_change().unwrap();
    let (funding, spend) = funding_and_spend(&addr, &change);
    let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
    psbt.inputs[0].witness_utxo = Some(funding.output[0].clone());
    psbt.inputs[0].witness_script = Some(lb.script(0, 0).unwrap());
    // As Core fills it in: every cosigner key with its BIP32 origin.
    for (w, k) in ws.iter().zip(&keys) {
        let u = w.unlock(None).unwrap();
        let path = DerivationPath::from_str("m/48'/1'/0'/2'/0/0").unwrap();
        let pk = u.master().derive_priv(&secp, &path).unwrap().private_key.public_key(&secp);
        psbt.inputs[0].bip32_derivation.insert(pk, (w.master_fingerprint().unwrap(), path));
        assert!(k.contains(&w.id));
    }
    let own = |s: &bitcoin::ScriptBuf| lb.scripts(5).contains(s);
    sign::check_psbt(&psbt, &own, &sign::Expected { payments: vec![], sweep_to: None, max_fee: 20_000 })
        .unwrap();

    // Two cosigners sign separate copies (as on two machines).
    let mut a = psbt.clone();
    let mut c = psbt.clone();
    assert_eq!(ws[0].sign_psbt(&ws[0].unlock(None).unwrap(), &mut a, 10).unwrap(), 1);
    assert_eq!(sign::summarize(&a, Network::Regtest, &|_| false).signature_status, vec!["1 of 2"]);
    assert!(sign::finalize(&mut a.clone()).is_err(), "one signature is not enough");
    assert_eq!(ws[2].sign_psbt(&ws[2].unlock(None).unwrap(), &mut c, 10).unwrap(), 1);
    a.combine(c).unwrap();
    assert_eq!(sign::summarize(&a, Network::Regtest, &|_| false).signature_status, vec!["complete"]);
    sign::finalize(&mut a).unwrap();
    let tx = a.extract_tx().unwrap();
    let wit = tx.input[0].witness.to_vec();
    assert_eq!(wit.len(), 4, "empty, 2 signatures, witness script");
    let ws_script = bitcoin::ScriptBuf::from_bytes(wit[3].clone());
    let mut cache = SighashCache::new(&tx);
    let h =
        cache.p2wsh_signature_hash(0, &ws_script, Amount::from_sat(200_000), EcdsaSighashType::All).unwrap();
    let (_, keys_in_script) = armory_wallet::lockbox::script_keys(ws_script.as_bytes()).unwrap();
    for sig in &wit[1..3] {
        let s = bitcoin::ecdsa::Signature::from_slice(sig).unwrap();
        assert!(keys_in_script.iter().any(|k| {
            let pk = bitcoin::PublicKey::from_slice(k).unwrap();
            secp.verify_ecdsa(&Message::from_digest(h.to_byte_array()), &s.signature, &pk.inner).is_ok()
        }));
    }
}

#[test]
fn armory_093_lockbox_spend() {
    let secp = Secp256k1::new();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy");
    let text = std::fs::read_to_string(dir.join("multisigs.txt")).unwrap();
    // rcEKCpQY: 2-of-2 of GDHFnMQ2 #0 and vzgEfJrJ #0.
    let legacy = read_legacy_lockboxes(&text, Network::Testnet)
        .unwrap()
        .into_iter()
        .find(|l| l.id == "rcEKCpQY")
        .unwrap();
    let lb = Lockbox::from_legacy(&legacy, Network::Testnet);
    let mut signers = Vec::new();
    for f in ["armory_GDHFnMQ2_.wallet", "armory_vzgEfJrJ_.wallet"] {
        let old = LegacyWallet::parse(&std::fs::read(dir.join(f)).unwrap()).unwrap();
        let mut w = ModernWallet::generate(Network::Testnet, f, 12, "", None, None, 0).unwrap().wallet;
        let mut u = w.unlock(None).unwrap();
        w.migrate_legacy(&mut u, &old, None, None).unwrap();
        signers.push(w);
    }
    let addr = lb.address(0, 0).unwrap();
    assert_eq!(addr.to_string(), "2N8J15VSbNfAajBgmtpshbbcLDuZ3PrmTdD");
    let (funding, spend) = funding_and_spend(&addr, &addr);
    let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
    psbt.inputs[0].non_witness_utxo = Some(funding.clone());
    psbt.inputs[0].redeem_script = Some(lb.script(0, 0).unwrap());
    let mut copies = Vec::new();
    for w in &signers {
        let mut p = psbt.clone();
        assert_eq!(w.sign_psbt(&w.unlock(None).unwrap(), &mut p, 5).unwrap(), 1);
        copies.push(p);
    }
    let mut merged = copies.remove(0);
    merged.combine(copies.remove(0)).unwrap();
    sign::finalize(&mut merged).unwrap();
    let tx = merged.extract_tx().unwrap();
    let parts: Vec<Vec<u8>> = tx.input[0]
        .script_sig
        .instructions()
        .map(|i| i.unwrap().push_bytes().map(|p| p.as_bytes().to_vec()).unwrap_or_default())
        .collect();
    assert_eq!(parts.len(), 4, "OP_0, two signatures, redeem script");
    let redeem = bitcoin::ScriptBuf::from_bytes(parts[3].clone());
    let cache = SighashCache::new(&tx);
    let h = cache.legacy_signature_hash(0, &redeem, 1).unwrap();
    let (_, keys) = armory_wallet::lockbox::script_keys(redeem.as_bytes()).unwrap();
    // Signatures must appear in script key order.
    for (sig, key) in parts[1..3].iter().zip(&keys) {
        let s = bitcoin::ecdsa::Signature::from_slice(sig).unwrap();
        let pk = bitcoin::PublicKey::from_slice(key).unwrap();
        secp.verify_ecdsa(&Message::from_digest(h.to_byte_array()), &s.signature, &pk.inner).unwrap();
    }
}
