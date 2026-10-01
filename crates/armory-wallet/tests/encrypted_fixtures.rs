//! Real encrypted wallets written by Armory (`fixtures/legacy/encrypted/`, see its README and
//! `docs/rust-rebuild/specs/01a-encrypted-wallet-verification.md`).

use std::path::PathBuf;

use armory_crypto::chain;
use armory_wallet::{Error, LegacyNetwork, LegacyWallet};

fn load(name: &str) -> (Vec<u8>, LegacyWallet) {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy/encrypted").join(name);
    let bytes = std::fs::read(&p).unwrap();
    let w = LegacyWallet::parse(&bytes).unwrap();
    (bytes, w)
}

#[test]
fn fake_wallet_123() {
    let (bytes, w) = load("FakeWallet123.wallet");
    assert_eq!(w.serialize(), bytes);
    assert_eq!(w.network, LegacyNetwork::Mainnet);
    assert_eq!(w.id(), "2Md4hKbcT");
    assert_eq!(w.label(), "Fake Wallet 1");
    assert!(w.is_encrypted());
    assert!(matches!(w.private_key(0, None), Err(Error::Locked)));
    assert!(matches!(w.unlock(b"wrong"), Err(Error::WrongPassphrase)));
    let key = w.unlock(b"FakeWallet123").unwrap();
    assert_eq!(hex::encode(&*key), "f31b9c5713e51702d27085ce85632c2f350866117b81bc10299860a03f28f764");
    let root = w.private_key(-1, Some(&key)).unwrap();
    assert_eq!(hex::encode(*root), "0d7039960bf05f742eafd4c1edb5f66b8a9cf752167772725842a704d1b5ef77");
    // A 2013 (pre-1.35a) wallet: the chain code is random, not derived from the root key.
    assert_ne!(chain::derive_chaincode(&root), w.chaincode().unwrap());
    assert_eq!(w.verify_chain(Some(&key)).unwrap(), 100);
    for i in 0..100 {
        w.private_key(i, Some(&key)).unwrap();
    }
}

#[test]
fn goatpig_legacy_with_pending_records() {
    let (bytes, w) = load("goatpig-legacy-testnet.wallet");
    assert_eq!(w.serialize(), bytes);
    assert_eq!(w.id(), "28m472Xbm");
    assert_eq!(w.label(), "legacy1");
    assert_eq!(w.highest_used, 2);
    let key = w.unlock(b"testnet").unwrap();
    assert_eq!(hex::encode(&*key), "ff2962603444f55299d6885fc050256a84f60dad2f9f665f282a502b1a36b1fe");
    let root = w.private_key(-1, Some(&key)).unwrap();
    assert_eq!(hex::encode(*root), "00c92e44ef9155e17d3067f020eb6f938ab416d882e598b45b7442a8979407ff");
    assert_eq!(chain::derive_chaincode(&root), w.chaincode().unwrap());

    for (idx, depth) in [(100, 1), (101, 2), (102, 3)] {
        let r = w.record(idx).unwrap();
        assert!(r.flags.pending, "idx {idx}");
        assert_eq!(r.chain_depth, depth);
        assert_eq!(r.iv, w.record(99).unwrap().iv, "pending records store idx 99's pair");
    }
    assert_eq!(w.verify_chain(Some(&key)).unwrap(), 103);
    let k102 = w.private_key(102, Some(&key)).unwrap();

    let mut m = w.clone();
    assert_eq!(m.materialise_pending(&key).unwrap(), 3);
    let m = LegacyWallet::parse(&m.serialize()).unwrap();
    assert!(!m.record(102).unwrap().flags.pending);
    assert_eq!(m.private_key(102, Some(&key)).unwrap(), k102);
}
