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
        cmd.arg("--datadir").arg(self.dir.path()).args(["--network", "testnet3"]).args(args);
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
    env.ok(&["wallet", "import", s(&fixture("armory_GDHFnMQ2_.wallet"))]);
    assert!(env.ok(&["wallet", "list"]).contains("GDHFnMQ2"));
    let json: serde_json::Value =
        serde_json::from_str(&env.ok(&["--json", "wallet", "show", "GDHF"])).unwrap();
    assert_eq!(json["highest_used_index"], 10);
    let used = env.ok(&["address", "list", "GDHFnMQ2"]);
    assert_eq!(used.lines().count(), 11);
    assert!(used.contains("muxkzd4sitPbMz4BXmkEJKT6ccshxDFsrn"));
    assert_eq!(env.ok(&["address", "new", "GDHFnMQ2"]).trim(), "muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG");
    env.ok(&["address", "label", "muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG", "rent"]);
    assert!(env.ok(&["address", "show", "muEePRR9ShvRm2nqeiJyD8pJRHPuww2ECG"]).contains("rent"));
    // Importing again without --replace is refused.
    assert!(!env.run(&["wallet", "import", s(&fixture("armory_GDHFnMQ2_.wallet"))], None).status.success());
}

#[test]
fn passphrase_lifecycle_and_exit_codes() {
    let env = Env::new();
    env.ok(&["wallet", "import", s(&fixture("armory_DZMmtb2v_.wallet"))]);
    let pw = env.file("pw", "correct horse\n");
    let bad = env.file("bad", "nope\n");
    env.ok(&[
        "wallet",
        "passphrase",
        "DZMmtb2v",
        "set",
        "--kdf-target-ms",
        "20",
        "--passphrase-file",
        s(&pw),
    ]);
    let o = env
        .run(&["address", "keys", "mnHywMYRuMyYeamyGhUPJLFSsoWbNAnsNz", "--passphrase-file", s(&bad)], None);
    assert_eq!(o.status.code(), Some(3));
    let out = env.ok(&["address", "keys", "mnHywMYRuMyYeamyGhUPJLFSsoWbNAnsNz", "--passphrase-file", s(&pw)]);
    assert!(out.contains("9295sDHkX1xDMzSxit3Bvi8GdLUQq1JFktBQFB8Ca45aLaw8neN"));
    // New addresses on an encrypted wallet need the passphrase and keep keys usable.
    env.ok(&["address", "new", "DZMmtb2v", "--passphrase-file", s(&pw)]);
    env.ok(&["wallet", "check", "DZMmtb2v", "--keys", "--passphrase-file", s(&pw)]);
    env.ok(&["wallet", "passphrase", "DZMmtb2v", "remove", "--passphrase-file", s(&pw)]);
    assert!(env.ok(&["wallet", "show", "DZMmtb2v"]).contains("Encrypted:      false"));
}

#[test]
fn create_import_key_and_watching_only() {
    let env = Env::new();
    let created: serde_json::Value =
        serde_json::from_str(&env.ok(&["--json", "wallet", "create", "--label", "Test", "--no-encrypt"]))
            .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    // Armory's pool rule: index 0 plus pool - (0 - (-1)) more addresses.
    assert_eq!(created["last_computed_index"], 9);
    let wif = armory_wallet::LegacyNetwork::Testnet.wif(&[0x11; 32]);
    let o = env.run(&["address", "import-key", &id], Some(&format!("{wif}\n")));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let imported = String::from_utf8(o.stdout).unwrap();
    let addr = imported.trim().trim_start_matches("Imported ").trim_end_matches('.');
    let keys = env.ok(&["address", "keys", addr]);
    assert!(keys.contains(&wif));
    env.ok(&["address", "remove-imported", addr]);
    assert!(!env.run(&["address", "show", addr], None).status.success());
    let dest = env.dir.path().join("wo.wallet");
    env.ok(&["wallet", "export-watchonly", &id, s(&dest)]);
    let bytes = std::fs::read(&dest).unwrap();
    let wo = armory_wallet::LegacyWallet::parse(&bytes).unwrap();
    assert!(wo.is_watching_only());
    assert_eq!(wo.id(), id);
}

#[test]
fn private_files() {
    let env = Env::new();
    env.ok(&["wallet", "import", s(&fixture("armory_vzgEfJrJ_.wallet"))]);
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
