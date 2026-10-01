//! End-to-end test against a real `bitcoind -regtest`. Skipped unless `ARMORY_BITCOIND` names a
//! bitcoind binary (Bitcoin Core 29 or newer). CI downloads one; locally:
//!
//! ```sh
//! ARMORY_BITCOIND=/usr/local/bin/bitcoind cargo test -p armory --test regtest -- --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use armory_node::{Auth, RpcClient};
use serde_json::{Value, json};

struct Node {
    child: Child,
    rpc: RpcClient,
    port: u16,
    dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.rpc.call(None, "stop", json!([]));
        std::thread::sleep(Duration::from_millis(500));
        let _ = self.child.kill();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start(bitcoind: &Path) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let child = Command::new(bitcoind)
        .arg("-regtest")
        .arg(format!("-datadir={}", dir.path().display()))
        .arg(format!("-rpcport={port}"))
        .arg(format!("-port={}", free_port()))
        .args(["-server", "-listen=0", "-fallbackfee=0.0002", "-txindex=0", "-printtoconsole=0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start bitcoind");
    let rpc = RpcClient::new(format!("127.0.0.1:{port}"), Auth::Cookie(dir.path().join("regtest/.cookie")));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if rpc.call(None, "getblockchaininfo", json!([])).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "bitcoind did not start");
        std::thread::sleep(Duration::from_millis(250));
    }
    Node { child, rpc, port, dir }
}

struct Cli<'a> {
    node: &'a Node,
    data: PathBuf,
}

impl Cli<'_> {
    fn run(&self, args: &[&str]) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_armory"))
            .arg("--datadir")
            .arg(&self.data)
            .args(["--network", "regtest", "--rpc-addr", &format!("127.0.0.1:{}", self.node.port)])
            .arg("--bitcoin-datadir")
            .arg(self.node.dir.path())
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        serde_json::from_str(&self.run(&a)).unwrap()
    }
}

fn mine(node: &Node, to: &str, n: u64) {
    node.rpc.call(None, "generatetoaddress", json!([n, to])).unwrap();
}

#[test]
fn regtest_end_to_end() {
    let Some(bitcoind) = std::env::var_os("ARMORY_BITCOIND") else {
        eprintln!("skipping: set ARMORY_BITCOIND to a bitcoind binary to run this test");
        return;
    };
    let node = start(Path::new(&bitcoind));
    let data = tempfile::tempdir().unwrap();
    let cli = Cli { node: &node, data: data.path().to_path_buf() };

    // A funded miner wallet inside bitcoind.
    node.rpc.call(None, "createwallet", json!(["miner"])).unwrap();
    let miner = node.rpc.call(Some("miner"), "getnewaddress", json!([])).unwrap();
    let miner = miner.as_str().unwrap().to_string();
    mine(&node, &miner, 101);

    // Armory wallet, watched by Core.
    let created = cli.json(&["wallet", "create", "--label", "E2E", "--no-encrypt", "--taproot"]);
    let id = created["id"].as_str().unwrap().to_string();
    assert!(cli.json(&["node", "status"])["blocks"].as_u64().unwrap() >= 101);
    cli.run(&["wallet", "sync", &id]);

    let a84 = cli.run(&["address", "new", &id]).trim().to_string();
    let a86 = cli.run(&["address", "new", &id, "--account", "1"]).trim().to_string();
    node.rpc.call(Some("miner"), "sendtoaddress", json!([a84, 1.0])).unwrap();
    node.rpc.call(Some("miner"), "sendtoaddress", json!([a86, 0.25])).unwrap();
    mine(&node, &miner, 1);
    assert_eq!(cli.json(&["balance", &id])["confirmed"], json!(125_000_000));

    // Send, with change back to the wallet.
    let sent = cli.json(&["send", &id, "--to", &format!("{miner}=0.3"), "--fee-rate", "2", "--yes"]);
    assert_eq!(sent["txid"].as_str().unwrap().len(), 64);
    mine(&node, &miner, 1);
    let bal = cli.json(&["balance", &id])["confirmed"].as_i64().unwrap();
    assert!(bal < 95_000_000 && bal > 94_900_000, "balance after send: {bal}");
    assert!(cli.json(&["history", &id]).as_array().unwrap().len() >= 3);

    // Offline flow: unsigned PSBT -> sign -> broadcast.
    let psbt = data.path().join("tx.psbt");
    cli.run(&[
        "send",
        &id,
        "--to",
        &format!("{miner}=0.1"),
        "--fee-rate",
        "2",
        "--unsigned-out",
        psbt.to_str().unwrap(),
    ]);
    cli.run(&["tx", "sign", psbt.to_str().unwrap(), "--wallet", &id]);
    cli.run(&["tx", "broadcast", psbt.to_str().unwrap()]);
    mine(&node, &miner, 1);

    // Migrate an Armory 0.93 wallet, fund a legacy address, sweep it into SegWit.
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy/armory_DZMmtb2v_.wallet");
    cli.run(&["wallet", "migrate", fixture.to_str().unwrap(), "--into", &id]);
    cli.run(&["wallet", "sync", &id, "--no-rescan"]);
    let legacy = cli.run(&["address", "new", &id, "--account", "2"]).trim().to_string();
    node.rpc.call(Some("miner"), "sendtoaddress", json!([legacy, 0.5])).unwrap();
    mine(&node, &miner, 1);
    let before = cli.json(&["balance", &id])["confirmed"].as_i64().unwrap();
    cli.run(&["wallet", "sweep-legacy", &id, "--fee-rate", "2", "--yes"]);
    mine(&node, &miner, 1);
    let after = cli.json(&["balance", &id])["confirmed"].as_i64().unwrap();
    assert!(before - after < 10_000, "sweep only costs the fee: {before} -> {after}");
    let utxos = cli.json(&["utxos", &id]);
    assert!(utxos.as_array().unwrap().iter().all(|u| u["address"].as_str().unwrap().starts_with("bcrt1")));
}
