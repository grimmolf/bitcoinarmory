//! End-to-end tests of the `armory` binary against the legacy fixtures.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy").join(name)
}

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self { dir: tempfile::tempdir().unwrap() }
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_armory"));
        cmd.arg("--datadir").arg(self.dir.path());
        if !args.contains(&"--network") {
            cmd.args(["--network", "testnet3"]);
        }
        cmd.args(args);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        {
            use std::io::Write;
            let mut sin = child.stdin.take().unwrap();
            if let Some(s) = stdin {
                sin.write_all(s.as_bytes()).unwrap();
            }
        }
        child.wait_with_output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let o = self.run(args, None);
        assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    }

    fn file(&self, name: &str, content: &str) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        p
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn import_list_receive_label() {
    let env = Env::new();
    env.ok(&["legacy", "wallet", "import", s(&fixture("armory_GDHFnMQ2_.wallet"))]);
    assert!(env.ok(&["legacy", "wallet", "list"]).contains("GDHFnMQ2"));
    let json: serde_json::Value =
        serde_json::from_str(&env.ok(&["--json", "legacy", "wallet", "show", "GDHF"])).unwrap();
    assert_eq!(json["highest_used_index"], 10);
    let used = env.ok(&["legacy", "address", "list", "GDHFnMQ2"]);
    assert_eq!(used.lines().count(), 11);
    assert!(used.contains("muxkzd4sitPbMz4BXmkEJKT6ccshxDFsrn"));
    assert_eq!(
        env.ok(&["legacy", "address", "new", "GDHFnMQ2"]).trim(),
        "muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG"
    );
    env.ok(&["legacy", "address", "label", "muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG", "rent"]);
    assert!(env.ok(&["legacy", "address", "show", "muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG"]).contains("rent"));
    // Importing again without --replace is refused.
    assert!(
        !env.run(&["legacy", "wallet", "import", s(&fixture("armory_GDHFnMQ2_.wallet"))], None)
            .status
            .success()
    );
}

#[test]
fn passphrase_lifecycle_and_exit_codes() {
    let env = Env::new();
    env.ok(&["legacy", "wallet", "import", s(&fixture("armory_DZMmtb2v_.wallet"))]);
    let pw = env.file("pw", "correct horse\n");
    let bad = env.file("bad", "nope\n");
    env.ok(&[
        "legacy",
        "wallet",
        "passphrase",
        "DZMmtb2v",
        "set",
        "--kdf-target-ms",
        "20",
        "--passphrase-file",
        s(&pw),
    ]);
    let o = env.run(
        &["legacy", "address", "keys", "mnHywMYRuMyYeamyGhUPJLFSsoWbNAnsNz", "--passphrase-file", s(&bad)],
        None,
    );
    assert_eq!(o.status.code(), Some(3));
    let out = env.ok(&[
        "legacy",
        "address",
        "keys",
        "mnHywMYRuMyYeamyGhUPJLFSsoWbNAnsNz",
        "--passphrase-file",
        s(&pw),
    ]);
    assert!(out.contains("9295sDHkX1xDMzSxit3Bvi8GdLUQq1JFktBQFB8Ca45aLaw8neN"));
    // New addresses on an encrypted wallet need the passphrase and keep keys usable.
    env.ok(&["legacy", "address", "new", "DZMmtb2v", "--passphrase-file", s(&pw)]);
    env.ok(&["legacy", "wallet", "check", "DZMmtb2v", "--keys", "--passphrase-file", s(&pw)]);
    env.ok(&["legacy", "wallet", "passphrase", "DZMmtb2v", "remove", "--passphrase-file", s(&pw)]);
    assert!(env.ok(&["legacy", "wallet", "show", "DZMmtb2v"]).contains("Encrypted:      false"));
}

#[test]
fn create_import_key_and_watching_only() {
    let env = Env::new();
    let created: serde_json::Value = serde_json::from_str(&env.ok(&[
        "--json",
        "legacy",
        "wallet",
        "create",
        "--label",
        "Test",
        "--no-encrypt",
    ]))
    .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    // Armory's pool rule: index 0 plus pool - (0 - (-1)) more addresses.
    assert_eq!(created["last_computed_index"], 9);
    let wif = armory_wallet::LegacyNetwork::Testnet.wif(&[0x11; 32]);
    let o = env.run(&["legacy", "address", "import-key", &id], Some(&format!("{wif}\n")));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let imported = String::from_utf8(o.stdout).unwrap();
    let addr = imported.trim().trim_start_matches("Imported ").trim_end_matches('.');
    let keys = env.ok(&["legacy", "address", "keys", addr]);
    assert!(keys.contains(&wif));
    env.ok(&["legacy", "address", "remove-imported", addr]);
    assert!(!env.run(&["legacy", "address", "show", addr], None).status.success());
    let dest = env.dir.path().join("wo.wallet");
    env.ok(&["legacy", "wallet", "export-watchonly", &id, s(&dest)]);
    let bytes = std::fs::read(&dest).unwrap();
    let wo = armory_wallet::LegacyWallet::parse(&bytes).unwrap();
    assert!(wo.is_watching_only());
    assert_eq!(wo.id(), id);
}

#[test]
fn private_files() {
    let env = Env::new();
    env.ok(&["legacy", "wallet", "import", s(&fixture("armory_vzgEfJrJ_.wallet"))]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let wdir = env.dir.path().join("testnet3/wallets");
        assert_eq!(std::fs::metadata(&wdir).unwrap().permissions().mode() & 0o777, 0o700);
        for e in std::fs::read_dir(&wdir).unwrap() {
            let m = e.unwrap().metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
    }
}

#[test]
fn receive_on_locked_wallet_needs_no_passphrase() {
    let env = Env::new();
    env.ok(&["legacy", "wallet", "import", s(&fixture("armory_DZMmtb2v_.wallet"))]);
    let pw = env.file("pw", "pw\n");
    env.ok(&[
        "legacy",
        "wallet",
        "passphrase",
        "DZMmtb2v",
        "set",
        "--kdf-target-ms",
        "20",
        "--passphrase-file",
        s(&pw),
    ]);
    // Twelve new addresses: the pool grows past the existing keys while locked.
    for _ in 0..12 {
        env.ok(&["legacy", "address", "new", "DZMmtb2v"]);
    }
    let path = env.dir.path().join("testnet3/wallets/armory_DZMmtb2v_.wallet");
    let w = armory_wallet::LegacyWallet::parse(&std::fs::read(&path).unwrap()).unwrap();
    assert!(w.chained().values().any(|r| r.flags.pending));
    // Unlocking resolves and rewrites the pending records.
    env.ok(&["legacy", "wallet", "check", "DZMmtb2v", "--keys", "--passphrase-file", s(&pw)]);
    let w = armory_wallet::LegacyWallet::parse(&std::fs::read(&path).unwrap()).unwrap();
    assert!(w.chained().values().all(|r| !r.flags.pending));
    let key = w.unlock(b"pw").unwrap();
    assert_eq!(w.verify_chain(Some(&key)).unwrap() as i64, w.last_computed_index() + 1);
}

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn modern_restore_vectors_and_receive() {
    let env = Env::new();
    let out = env.run(
        &["--network", "mainnet", "wallet", "restore", "--no-encrypt", "--taproot"],
        Some(&format!("{ABANDON}\n")),
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let a = env.ok(&["--network", "mainnet", "address", "new", "73c5da0a"]);
    assert_eq!(a.trim(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    let t = env.ok(&["--network", "mainnet", "address", "new", "73c5da0a", "--account", "1"]);
    assert_eq!(t.trim(), "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
    env.ok(&[
        "--network",
        "mainnet",
        "address",
        "label",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "salary",
    ]);
    let list = env.ok(&["--network", "mainnet", "address", "list", "73c5da0a"]);
    assert!(list.contains("salary"));
    let d = env.ok(&["--network", "mainnet", "wallet", "descriptors", "73c5da0a"]);
    assert!(d.lines().any(|l| l.starts_with("wpkh([73c5da0a/84h/0h/0h]xpub")));
    assert!(d.lines().any(|l| l.starts_with("tr([73c5da0a/86h/0h/0h]xpub")));
}

#[test]
fn modern_create_encrypted_seed_and_passphrase() {
    let env = Env::new();
    let pw = env.file("pw", "secret pass\n");
    let fast = ["--kdf-memory-mib", "1", "--kdf-iterations", "1"];
    let mut args = vec!["--json", "wallet", "create", "--label", "Savings", "--passphrase-file", s(&pw)];
    args.extend(fast);
    let created: serde_json::Value = serde_json::from_str(&env.ok(&args)).unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["mnemonic"].as_str().unwrap().split(' ').count(), 24);
    assert_eq!(created["protection"], "encrypted");
    // Receiving needs no passphrase.
    assert!(env.ok(&["address", "new", &id]).trim().starts_with("tb1q"));
    let bad = env.file("bad", "nope\n");
    let o = env.run(&["wallet", "show-seed", &id, "--passphrase-file", s(&bad)], None);
    assert_eq!(o.status.code(), Some(3));
    let seed: serde_json::Value =
        serde_json::from_str(&env.ok(&["--json", "wallet", "show-seed", &id, "--passphrase-file", s(&pw)]))
            .unwrap();
    assert_eq!(seed["mnemonic"], created["mnemonic"]);
    let mut rm = vec!["wallet", "passphrase", &id, "remove", "--passphrase-file", s(&pw)];
    rm.extend(fast);
    env.ok(&rm);
    assert!(env.ok(&["wallet", "show", &id]).contains("unencrypted"));
}

#[test]
fn modern_migrate_legacy_wallet() {
    let env = Env::new();
    let out =
        env.ok(&["--json", "wallet", "migrate", s(&fixture("armory_GDHFnMQ2_.wallet")), "--no-encrypt"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["accounts"][1]["kind"], "legacy-1.35");
    assert_eq!(v["accounts"][1]["legacy_wallet_id"], "GDHFnMQ2");
    let next = env.ok(&["address", "new", &id, "--account", "1"]);
    assert_eq!(next.trim(), "muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG");
    // A second legacy wallet goes into the same modern wallet.
    env.ok(&["wallet", "migrate", s(&fixture("armory_DZMmtb2v_.wallet")), "--into", &id]);
    let show: serde_json::Value = serde_json::from_str(&env.ok(&["--json", "wallet", "show", &id])).unwrap();
    assert_eq!(show["accounts"].as_array().unwrap().len(), 3);
    let d = env.ok(&["wallet", "descriptors", &id, "--account", "2", "--legacy-count", "5"]);
    assert_eq!(d.lines().count(), 5);
    assert!(d.lines().all(|l| l.starts_with("pkh(04")));
}

#[test]
fn modern_signet_and_check() {
    let env = Env::new();
    let created: serde_json::Value = serde_json::from_str(&env.ok(&[
        "--json",
        "--network",
        "signet",
        "wallet",
        "create",
        "--label",
        "S",
        "--no-encrypt",
        "--taproot",
    ]))
    .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    assert!(env.ok(&["--network", "signet", "address", "new", &id]).trim().starts_with("tb1q"));
    assert!(
        env.ok(&["--network", "signet", "address", "new", &id, "--account", "1"]).trim().starts_with("tb1p")
    );
    assert!(env.ok(&["--network", "signet", "wallet", "check", &id]).contains("matches the secrets"));
    env.ok(&[
        "--network",
        "signet",
        "wallet",
        "migrate",
        s(&fixture("armory_vzgEfJrJ_.wallet")),
        "--into",
        &id,
    ]);
    let legacy_addr = env.ok(&["--network", "signet", "address", "new", &id, "--account", "2"]);
    // Receiving resumes at the legacy wallet's next unused index (highest used = 4).
    let old = armory_wallet::LegacyWallet::parse(&std::fs::read(fixture("armory_vzgEfJrJ_.wallet")).unwrap())
        .unwrap();
    assert_eq!(legacy_addr.trim(), old.address(old.record(5).unwrap()));
    env.ok(&["--network", "signet", "wallet", "check", &id]);
}

fn create_plain(env: &Env) -> String {
    let v: serde_json::Value =
        serde_json::from_str(&env.ok(&["--json", "wallet", "create", "--label", "B", "--no-encrypt"]))
            .unwrap();
    v["id"].as_str().unwrap().to_string()
}

fn code_from(stderr: &[u8]) -> String {
    let e = String::from_utf8_lossy(stderr);
    let line = e.lines().find(|l| l.starts_with("SecurePrint code")).expect("code printed");
    line.split(": ").nth(1).unwrap().split_whitespace().next().unwrap().to_string()
}

#[test]
fn paper_backup_test_and_restore() {
    let env = Env::new();
    let id = create_plain(&env);
    let sheet = env.dir.path().join("sheet.txt");
    env.ok(&["backup", "paper", &id, "-o", s(&sheet)]);
    assert!(env.ok(&["restore", "paper", "--file", s(&sheet), "--test", &id]).starts_with("PASS"));
    let o = env.run(&["restore", "paper", "--file", s(&sheet), "--test", "deadbeef"], None);
    assert_eq!(o.status.code(), Some(4));
    // Restore into a fresh data directory gives the same wallet.
    let other = Env::new();
    let v: serde_json::Value =
        serde_json::from_str(&other.ok(&["--json", "restore", "paper", "--file", s(&sheet), "--no-encrypt"]))
            .unwrap();
    assert_eq!(v["id"].as_str().unwrap(), id);
}

#[test]
fn secureprint_paper_and_fragments() {
    let env = Env::new();
    let id = create_plain(&env);
    let sheet = env.dir.path().join("sp.txt");
    let o = env.run(&["backup", "paper", &id, "--secureprint", "-o", s(&sheet)], None);
    assert!(o.status.success());
    let code = env.file("code", &code_from(&o.stderr));
    let text = std::fs::read_to_string(&sheet).unwrap();
    assert!(!text.contains("Recovery words"), "SecurePrint sheets must not show the words");
    env.ok(&[
        "restore",
        "paper",
        "--secureprint",
        "--code-file",
        s(&code),
        "--file",
        s(&sheet),
        "--test",
        &id,
    ]);

    let dir = env.dir.path().join("frags");
    let o = env.run(
        &["backup", "fragments", &id, "-m", "2", "-n", "3", "--secureprint", "--output-dir", s(&dir)],
        None,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let fcode = env.file("fcode", &code_from(&o.stderr));
    let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    assert_eq!(files.len(), 3);
    let two = format!(
        "{}\n{}",
        std::fs::read_to_string(&files[2]).unwrap(),
        std::fs::read_to_string(&files[0]).unwrap()
    );
    let both = env.file("two.txt", &two);
    env.ok(&["restore", "fragments", "--file", s(&both), "--code-file", s(&fcode), "--test", &id]);
    let one = env.file("one.txt", &std::fs::read_to_string(&files[1]).unwrap());
    assert!(
        !env.run(&["restore", "fragments", "--file", s(&one), "--code-file", s(&fcode), "--test", &id], None)
            .status
            .success()
    );
}

#[test]
fn restore_armory_093_paper_and_fragments() {
    // Single sheet of the GDHFnMQ2 fixture, as Armory 0.93 printed it (1.35c).
    let old = armory_wallet::LegacyWallet::parse(&std::fs::read(fixture("armory_GDHFnMQ2_.wallet")).unwrap())
        .unwrap();
    let (root, cc) = old.root_secret(None).unwrap();
    let (sheet, ver) = armory_wallet::backup::legacy_sheet(&root, &cc, false).unwrap();
    assert_eq!(ver, "1.35c");
    let env = Env::new();
    let f = env.file("old.txt", &format!("Root Key: {}\n          {}\n", sheet.lines[0], sheet.lines[1]));
    assert!(
        env.ok(&["restore", "paper", "--legacy", "--file", s(&f), "--test", "GDHFnMQ2"]).starts_with("PASS")
    );
    let v: serde_json::Value = serde_json::from_str(&env.ok(&[
        "--json",
        "restore",
        "paper",
        "--legacy",
        "--file",
        s(&f),
        "--no-encrypt",
    ]))
    .unwrap();
    assert_eq!(v["accounts"][1]["legacy_wallet_id"], "GDHFnMQ2");
    let id = v["id"].as_str().unwrap();
    assert_eq!(
        env.ok(&["address", "new", id, "--account", "1"]).trim(),
        "muxkzd4sitPbMz4BXmkEJKT6ccshxDFsrn"
    );

    // Fragments printed by Armory 0.93 (spec 02 vector A, mainnet), two of them, one SecurePrint.
    let frags = env.file(
        "frags.txt",
        "ID: 8201 bad4 ab48 0100\nF1: jrie ehij fswu hnwk  urew husa khng gtnw  tnjk\nF2: oana aksg dukw ofsr  tjeh ttsa dwka oern  fuio\n\n\
         ID: 0203 bad4 ab48 0100\nF1: jeat afij twhe dwjr  iafj otok uwnk roin  ghdu\nF2: kfgf fhwh drjd hudr  fkri dusu enhk ggke  wruk\n",
    );
    let code = env.file("c", "8rDHqahJzK8\n");
    let out = env.ok(&[
        "--network",
        "mainnet",
        "restore",
        "fragments",
        "--file",
        s(&frags),
        "--code-file",
        s(&code),
        "--test",
        "2c36x2XPM",
    ]);
    assert!(out.starts_with("PASS"), "{out}");
}

#[test]
fn full_sheet_covers_migrated_legacy_wallet() {
    let env = Env::new();
    let id = create_plain(&env);
    env.ok(&["wallet", "migrate", s(&fixture("armory_DZMmtb2v_.wallet")), "--into", &id]);
    let sheet = env.dir.path().join("full.txt");
    env.ok(&["backup", "paper", &id, "-o", s(&sheet)]);
    env.ok(&["restore", "paper", "--file", s(&sheet), "--test", &id]);
    assert!(
        env.ok(&["restore", "paper", "--legacy", "--file", s(&sheet), "--test", "DZMmtb2v"])
            .starts_with("PASS")
    );
}
