//! Golden-fixture tests: the three TIAB testnet wallets in `fixtures/legacy/`
//! (spec 01 §14.4, `pytest/testArmoryDTiab.py:52-108`).

use std::path::PathBuf;

use armory_crypto::chain;
use armory_crypto::kdf::KdfParams;
use armory_wallet::legacy::Entry;
use armory_wallet::store::{Recovery, WalletFile, WalletPaths};
use armory_wallet::{Error, LegacyNetwork, LegacyWallet};

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

struct Expect {
    id: &'static str,
    label: &'static str,
    created: u64,
    highest: i64,
    last: i64,
    root160: &'static str,
    chaincode: &'static str,
    keys: &'static [(i64, &'static str, &'static str)],
}

const WALLETS: [Expect; 3] = [
    Expect {
        id: "GDHFnMQ2",
        label: "Primary Wallet",
        created: 1392443085,
        highest: 10,
        last: 20,
        root160: "536364abd1d2084bf229e0d3805e7b3913aaf011",
        chaincode: "e7a347003d10e1be87125da4dde514a009c721fcb4f86844bf5f66cf186eda84",
        keys: &[
            (0, "muxkzd4sitPbMz4BXmkEJKT6ccshxDFsrn", "92vsXfvjpbTj1sN75VSV2M7DWyqoVx5nayp3dE7ZaG9rRVRYU4P"),
            (1, "mtZ2d1jFZ9YNp3Ku5Fb2u8Tfu3RgimBHAD", "934MLhycJEAWL4kMbFt6JRSkNcgEtQXN3ha6Wh8WZyD85cZZZ4N"),
            (2, "mhrpYhQLgYgAvYs1A4E8Z4Dv4ZoZPyLbLS", "91rTQa47dLQhNGDenejW9qxcMTL73GRG347zKfa3qVvzun7ZcNe"),
            (7, "mikxgMUqkk6Tts1D39Hhx6wKEeQbBH3ons", "92fXG1foeHfn8DYEwTXggCPrFEEY6KpokqoJkp9EhpJw5boc3GY"),
        ],
    },
    Expect {
        id: "vzgEfJrJ",
        label: "Secondary Wallet with a really r",
        created: 1392649402,
        highest: 4,
        last: 14,
        root160: "65971cb5434bedf34648378b167c02430bab3235",
        chaincode: "9126a905db7c9bb1bc640106c010a1a6be9aee1e968edf8e30be40620648cbac",
        keys: &[
            (0, "mzkKrXNPU6nfBpZCKLmwueb9MvSFaKPDMD", "91jZJ2BnJbk4B6zpqzJqVfbtaq4RMaPPvP7USr9rtWXusSAYrq7"),
            (1, "n2DLXxVZSNBfzXsAm4HewpsfAGBpgTW6DH", "93LLsm4n19Dwbp6zbnmuvHmMjEJFR23h4xstnDnEBYMWSkXaFMT"),
            (2, "mhbmvVedo4i67maX6pfw9trcBWQQ3yXgkB", "92aUXStPSfHDXydGh9MsBnnyacNzJwgWBC4G8W5BiTFkTJpeHEH"),
            (3, "mk7pAQ7YdmnwWaGFCgwiKiEbaGjyEsSVUE", "92gYPs8i6qvSmc8moBAaWLB7M16kX5MBpbGoUygUmQTdrxkNnwR"),
        ],
    },
    Expect {
        id: "DZMmtb2v",
        label: "Third Wallet",
        created: 1399999349,
        highest: 3,
        last: 13,
        root160: "b1a049c9eaea2746b36fc317d4096571aee71c81",
        chaincode: "a76fa204771ff423a0cf5b6abe1ea9166583e66449df057ba6ad8768299fa4b1",
        keys: &[
            (0, "mnHywMYRuMyYeamyGhUPJLFSsoWbNAnsNz", "9295sDHkX1xDMzSxit3Bvi8GdLUQq1JFktBQFB8Ca45aLaw8neN"),
            (1, "mpXd2u8fPVYdL1Nf9bZ4EFnqhkNyghGLxL", "92Mic29J44mKLn4qKXm31mMv45BtEnywBnJh36jn1Rk2RT9PTsK"),
            (2, "mmfN9oj2wtMTCACKJz7fUcDeAczz4kucvV", "92ymyLuiEUJJz5madzhPtBTa3of46vLXDSuFPNMAA6DMLSeKA8S"),
        ],
    },
];

fn load(id: &str) -> (Vec<u8>, LegacyWallet) {
    let bytes = fixture(&format!("armory_{id}_.wallet"));
    let w = LegacyWallet::parse(&bytes).unwrap();
    (bytes, w)
}

#[test]
fn header_and_identity() {
    for e in &WALLETS {
        let (_, w) = load(e.id);
        assert_eq!(w.id(), e.id);
        assert_eq!(w.network, LegacyNetwork::Testnet);
        assert_eq!(w.label(), e.label);
        assert_eq!(w.create_date, e.created);
        assert_eq!(w.highest_used, e.highest);
        assert_eq!(w.last_computed_index(), e.last);
        assert!(!w.is_encrypted() && !w.is_watching_only());
        assert_eq!(hex::encode(w.root.addr160), e.root160);
        assert_eq!(hex::encode(w.chaincode().unwrap()), e.chaincode);
        // All three are 1.35c wallets: the chain code follows from the root key.
        let (root, cc) = w.root_secret(None).unwrap();
        assert_eq!(chain::derive_chaincode(&root), cc);
        assert_eq!(chain::wallet_id_from_root(&root, &cc, 0x6f).unwrap(), e.id);
        assert!(!w.repaired);
    }
}

#[test]
fn byte_identical_roundtrip_and_backup_twin() {
    for e in &WALLETS {
        let (bytes, w) = load(e.id);
        assert_eq!(w.serialize(), bytes, "{}", e.id);
        assert_eq!(fixture(&format!("armory_{}_backup.wallet", e.id)), bytes);
    }
}

#[test]
fn chain_addresses_and_wifs() {
    for e in &WALLETS {
        let (_, w) = load(e.id);
        assert_eq!(w.verify_chain(None).unwrap() as i64, e.last + 1);
        for (idx, addr, wif) in e.keys {
            let r = w.record(*idx).unwrap();
            assert_eq!(w.address(r), *addr);
            let k = w.private_key(*idx, None).unwrap();
            assert_eq!(w.network.wif(&k), *wif);
        }
    }
}

#[test]
fn next_unused_address() {
    let (_, w) = load("GDHFnMQ2");
    let next = w.peek_next_unused().unwrap();
    assert_eq!(next.chain_index, 11);
    assert_eq!(w.address(next), "muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG");
}

#[test]
fn comments() {
    let (_, w) = load("GDHFnMQ2");
    let ac = w.address_comments();
    assert_eq!(ac.len(), 6);
    assert!(ac.values().all(|c| c == "[[ Change received ]]"));
    let tc = w.tx_comments();
    assert_eq!(tc.len(), 1);
    let (hash, text) = tc.iter().next().unwrap();
    assert_eq!(text, "Funding 2-of-3");
    let mut display = *hash;
    display.reverse();
    assert!(hex::encode(display).starts_with("111842cb"));
}

fn fast_kdf() -> KdfParams {
    KdfParams { memory_bytes: 1024, iterations: 1, salt: [7; 32] }
}

#[test]
fn encrypt_unlock_rekey_decrypt() {
    let (orig, mut w) = load("DZMmtb2v");
    let expected: Vec<_> = (0..=w.last_computed_index()).map(|i| w.private_key(i, None).unwrap()).collect();

    w.change_encryption(None, Some((fast_kdf(), b"abcde"))).unwrap();
    assert!(w.is_encrypted());
    // Survives a serialize/parse cycle.
    let mut w = LegacyWallet::parse(&w.serialize()).unwrap();
    assert!(matches!(w.private_key(0, None), Err(Error::Locked)));
    assert!(matches!(w.unlock(b"wrong"), Err(Error::WrongPassphrase)));
    let key = w.unlock(b"abcde").unwrap();
    for (i, k) in expected.iter().enumerate() {
        assert_eq!(w.private_key(i as i64, Some(&key)).unwrap(), *k);
    }

    let new_params = KdfParams { memory_bytes: 2048, iterations: 2, salt: [9; 32] };
    w.change_encryption(Some(&key), Some((new_params, b"new pass"))).unwrap();
    assert!(w.unlock(b"abcde").is_err());
    let key2 = w.unlock(b"new pass").unwrap();
    assert_eq!(w.private_key(5, Some(&key2)).unwrap(), expected[5]);

    w.change_encryption(Some(&key2), None).unwrap();
    assert!(!w.is_encrypted());
    assert_eq!(w.private_key(5, None).unwrap(), expected[5]);
    // Only IVs and the KDF block differ from the original file now.
    assert_eq!(w.serialize().len(), orig.len());
}

#[test]
fn pending_keys_created_while_locked() {
    let (_, mut w) = load("vzgEfJrJ");
    w.change_encryption(None, Some((fast_kdf(), b"pw"))).unwrap();
    let w0 = LegacyWallet::parse(&w.serialize()).unwrap();
    let mut w = w0.clone();
    let first_new = w.last_computed_index() + 1;
    for _ in 0..3 {
        let r = w.extend_chain(None).unwrap();
        assert!(r.flags.pending);
    }
    let w = LegacyWallet::parse(&w.serialize()).unwrap();
    assert_eq!(w.record(first_new + 2).unwrap().chain_depth, 3);
    assert_eq!(w.verify_chain(None).unwrap() as i64, first_new + 3);
    let key = w.unlock(b"pw").unwrap();
    // Same keys as extending an unlocked copy.
    let mut unlocked = w0.clone();
    let k0 = unlocked.unlock(b"pw").unwrap();
    for _ in 0..3 {
        unlocked.extend_chain(Some(&k0)).unwrap();
    }
    for i in first_new..first_new + 3 {
        assert_eq!(w.private_key(i, Some(&key)).unwrap(), unlocked.private_key(i, Some(&k0)).unwrap());
    }
    let mut m = w.clone();
    assert_eq!(m.materialise_pending(&key).unwrap(), 3);
    assert!(m.chained().values().all(|r| !r.flags.pending));
    assert_eq!(
        m.private_key(first_new + 2, Some(&key)).unwrap(),
        w.private_key(first_new + 2, Some(&key)).unwrap()
    );
}

#[test]
fn watching_only_copy() {
    let (_, w) = load("GDHFnMQ2");
    let mut wo = LegacyWallet::parse(&w.watching_only_copy().serialize()).unwrap();
    assert!(wo.is_watching_only());
    assert_eq!(wo.id(), w.id());
    assert_eq!(wo.label(), "Primary Wallet (Watch)");
    assert!(matches!(wo.private_key(0, None), Err(Error::WatchingOnly)));
    let r = wo.extend_chain(None).unwrap().clone();
    assert!(!r.flags.has_priv && r.flags.has_pub);
    let mut full = w.clone();
    let r2 = full.extend_chain(None).unwrap();
    assert_eq!(r.addr160, r2.addr160);
    assert_eq!(wo.verify_chain(None).unwrap(), 22);
    assert_eq!(wo.address_comments().len(), 6);
}

#[test]
fn restore_from_root_matches_fixture() {
    let (_, w) = load("GDHFnMQ2");
    let (root, _) = w.root_secret(None).unwrap();
    let r =
        LegacyWallet::from_root(LegacyNetwork::Testnet, "Restored", "", &root, None, None, 30, 0).unwrap();
    assert_eq!(r.id(), "GDHFnMQ2");
    for i in 0..=20 {
        assert_eq!(r.record(i).unwrap().addr160, w.record(i).unwrap().addr160);
    }
}

#[test]
fn legacy_unit_wallet_id() {
    // pytest/testPyBtcWallet.py:25-32: root aa x32, chain ee x32, testnet
    let w =
        LegacyWallet::from_root(LegacyNetwork::Testnet, "t", "", &[0xaa; 32], Some([0xee; 32]), None, 5, 0)
            .unwrap();
    assert_eq!(w.id(), "3VB8XSoY");
    assert_eq!(hex::encode(w.record(0).unwrap().addr160), "fb80e6fd042fa24178b897a6a70e1ae7eb56a20a");
}

#[test]
fn import_and_remove_key() {
    let (_, mut w) = load("DZMmtb2v");
    let h = w.import_private_key(&[0x11; 32], None).unwrap();
    let w2 = LegacyWallet::parse(&w.serialize()).unwrap();
    assert_eq!(w2.imported().len(), 1);
    assert_eq!(*w2.private_key_for(&h, None).unwrap(), [0x11; 32]);
    let mut w3 = w2.clone();
    assert!(matches!(w3.remove_imported(&w3.record(0).unwrap().addr160.clone()), Err(Error::NotImported)));
    let len = w3.serialize().len();
    w3.remove_imported(&h).unwrap();
    assert_eq!(w3.serialize().len(), len);
    let w4 = LegacyWallet::parse(&w3.serialize()).unwrap();
    assert!(w4.imported().is_empty());
    assert!(w4.entries.iter().any(|e| matches!(e, Entry::Deleted { .. })));
}

#[test]
fn file_store_and_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let (_, w) = load("DZMmtb2v");
    let path = dir.path().join(w.default_file_name());
    let mut f = WalletFile::create(&path, w).unwrap();
    let paths = WalletPaths::new(&path);
    assert!(paths.backup.exists());
    f.wallet.set_labels("Renamed", "x").unwrap();
    f.save().unwrap();
    assert_eq!(std::fs::read(&paths.main).unwrap(), std::fs::read(&paths.backup).unwrap());

    // Simulate a crash during the main-file update: main is garbage, main flag present.
    std::fs::write(&paths.main, b"garbage").unwrap();
    std::fs::write(&paths.main_flag, b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&paths.main, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let f = WalletFile::open(&path).unwrap();
    assert_eq!(f.recovery, Recovery::RestoredMainFromBackup);
    assert_eq!(f.wallet.label(), "Renamed");
    assert!(!paths.main_flag.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&paths.main, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(WalletFile::open(&path), Err(Error::InsecurePermissions { .. })));
    }
}
