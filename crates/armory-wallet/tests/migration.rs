//! Migrating legacy v1.35 wallets into the modern v2 format.

use std::path::PathBuf;

use armory_wallet::LegacyWallet;
use armory_wallet::modern::{AccountKind, KdfParams, ModernWallet};
use bitcoin::Network;

fn legacy(path: &str) -> LegacyWallet {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy").join(path);
    LegacyWallet::parse(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn migrate_unencrypted_testnet_wallet() {
    let old = legacy("armory_GDHFnMQ2_.wallet");
    let mut nw = ModernWallet::generate(Network::Testnet, "Main", 24, "", None, None, 0).unwrap();
    let w = &mut nw.wallet;
    let mut u = w.unlock(None).unwrap();
    let acct = w.migrate_legacy(&mut u, &old, None, None).unwrap();
    assert_eq!(w.accounts[acct].kind, AccountKind::Legacy135);
    for i in 0..=20 {
        let r = old.record(i).unwrap();
        assert_eq!(w.address(acct, 0, i as u32).unwrap().to_string(), old.address(r));
    }
    // Receiving continues where Armory 0.93 left off.
    assert_eq!(w.next_receive(acct).unwrap().to_string(), "muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG");
    assert_eq!(w.address_labels.len(), 6);
    assert!(w.tx_comments.values().any(|c| c == "Funding 2-of-3"));
    // Keys survive a save/load cycle and match the legacy wallet.
    let w2 = ModernWallet::from_json(&w.to_json().unwrap()).unwrap();
    let u2 = w2.unlock(None).unwrap();
    assert_eq!(w2.legacy_private_key(&u2, acct, 7).unwrap(), old.private_key(7, None).unwrap());
    assert_eq!(w2.public_descriptors(acct, 21).unwrap().len(), 21);
    assert!(w2.public_descriptors(acct, 21).unwrap()[0].starts_with("pkh(04"));
    // Migrating twice is refused.
    let mut u3 = w2.unlock(None).unwrap();
    assert!(w.clone().migrate_legacy(&mut u3, &old, None, None).is_err());
}

#[test]
fn migrate_encrypted_mainnet_wallet() {
    let old = legacy("encrypted/FakeWallet123.wallet");
    let key = old.unlock(b"FakeWallet123").unwrap();
    let fast = KdfParams::with_cost(64, 1);
    let mut nw =
        ModernWallet::generate(Network::Bitcoin, "Main", 24, "", Some((b"new pass", fast)), None, 0).unwrap();
    let w = &mut nw.wallet;
    let mut u = w.unlock(Some(b"new pass")).unwrap();
    let acct = w.migrate_legacy(&mut u, &old, Some(&key), Some(b"new pass")).unwrap();
    assert!(w.is_encrypted());
    let u2 = w.unlock(Some(b"new pass")).unwrap();
    assert_eq!(w2_key(w, &u2, acct, 42), *old.private_key(42, Some(&key)).unwrap());
    assert_eq!(w.address(acct, 0, 0).unwrap().to_string(), old.address(old.record(0).unwrap()));
    assert!(w.address(0, 0, 0).unwrap().to_string().starts_with("bc1q"));
    // Wrong network is refused.
    let mut t = ModernWallet::generate(Network::Testnet, "T", 12, "", None, None, 0).unwrap().wallet;
    let mut tu = t.unlock(None).unwrap();
    assert!(t.migrate_legacy(&mut tu, &old, Some(&key), None).is_err());
}

fn w2_key(w: &ModernWallet, u: &armory_wallet::modern::Unlocked, acct: usize, i: u32) -> [u8; 32] {
    *w.legacy_private_key(u, acct, i).unwrap()
}
