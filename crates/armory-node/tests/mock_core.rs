//! The Core backend against a mock Bitcoin Core JSON-RPC server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use armory_node::core::{Balances, Core, NodeConfig, Rescan};
use armory_node::{NodeError, RpcError};
use armory_wallet::modern::ModernWallet;
use bitcoin::Network;
use serde_json::{Value, json};

type Calls = Arc<Mutex<Vec<(String, String, Value)>>>;

struct Mock {
    addr: String,
    calls: Calls,
    _dir: tempfile::TempDir,
    cookie: std::path::PathBuf,
}

fn handler(path: &str, method: &str, params: &Value) -> Result<Value, (i64, &'static str)> {
    let _ = path;
    Ok(match method {
        "getblockchaininfo" => {
            json!({"chain": "regtest", "blocks": 120, "headers": 120, "verificationprogress": 1.0, "initialblockdownload": false, "pruned": false})
        }
        "getnetworkinfo" => json!({"version": 290100, "subversion": "/Satoshi:29.1.0/", "relayfee": 0.00001}),
        "listwallets" => json!([]),
        "loadwallet" => return Err((-18, "Path does not exist")),
        "createwallet" => json!({"name": params[0]}),
        "importdescriptors" => {
            // Like Core after a keypool top-up: ranged descriptors already cover [0,999].
            json!(
                params[0]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| match r["range"][1].as_u64() {
                        Some(end) if end < 999 => json!({"success": false, "error": {"code": -8,
                        "message": "new range must include current range = [0,999]"}}),
                        _ => json!({"success": true}),
                    })
                    .collect::<Vec<_>>()
            )
        }
        "getbalances" => json!({"mine": {"trusted": 1.5, "untrusted_pending": 0.00012345, "immature": 0.0}}),
        "listtransactions" => json!([
            {"txid": "aa", "category": "receive", "amount": 1.5, "confirmations": 10, "time": 100, "address": "bcrt1qx", "vout": 0},
            {"txid": "bb", "category": "receive", "amount": 0.00012345, "confirmations": 0, "time": 200, "address": "bcrt1qy", "vout": 1}
        ]),
        "listunspent" => {
            json!([{"txid": "aa", "vout": 0, "address": "bcrt1qx", "amount": 1.5, "confirmations": 10, "desc": "wpkh(...)"}])
        }
        // Target 1 simulates a hostile node: 1 BTC/kvB = 100 000 sat/vB.
        "estimatesmartfee" if params[0] == 1 => json!({"feerate": 1.0, "blocks": 1}),
        "estimatesmartfee" => json!({"feerate": 0.00012, "blocks": 6}),
        "testmempoolaccept" => {
            if params[0][0] == "bad" {
                json!([{"allowed": false, "reject-reason": "min relay fee not met"}])
            } else {
                json!([{"allowed": true}])
            }
        }
        "sendrawtransaction" => json!("c0ffee"),
        "walletcreatefundedpsbt" => json!({"psbt": "cHNidP8=", "fee": 0.0001, "changepos": 1}),
        _ => return Err((-32601, "Method not found")),
    })
}

fn start() -> Mock {
    let dir = tempfile::tempdir().unwrap();
    let cookie = dir.path().join(".cookie");
    std::fs::write(&cookie, "__cookie__:s3cret\n").unwrap();
    let expected = format!("Basic {}", base64_encode("__cookie__:s3cret"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let calls: Calls = Arc::default();
    let c2 = calls.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut r = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
            let (mut len, mut auth) = (0usize, String::new());
            loop {
                line.clear();
                r.read_line(&mut line).unwrap();
                let l = line.trim_end();
                if l.is_empty() {
                    break;
                }
                let (k, v) = l.split_once(':').unwrap();
                match k.to_ascii_lowercase().as_str() {
                    "content-length" => len = v.trim().parse().unwrap(),
                    "authorization" => auth = v.trim().to_string(),
                    _ => {}
                }
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).unwrap();
            if auth != expected {
                let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
                continue;
            }
            let req: Value = serde_json::from_slice(&body).unwrap();
            let method = req["method"].as_str().unwrap().to_string();
            c2.lock().unwrap().push((path.clone(), method.clone(), req["params"].clone()));
            let (status, resp) = match handler(&path, &method, &req["params"]) {
                Ok(v) => (200, json!({"result": v, "error": null, "id": req["id"]})),
                Err((code, msg)) => {
                    (500, json!({"result": null, "error": {"code": code, "message": msg}, "id": req["id"]}))
                }
            };
            let b = resp.to_string();
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
                    b.len()
                )
                .as_bytes(),
            );
        }
    });
    Mock { addr, calls, _dir: dir, cookie }
}

fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

fn core(m: &Mock, network: Network) -> Core {
    Core::new(
        &NodeConfig {
            rpc_addr: Some(m.addr.clone()),
            cookie_file: Some(m.cookie.clone()),
            ..Default::default()
        },
        network,
    )
}

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn status_auth_and_chain_check() {
    let m = start();
    let s = core(&m, Network::Regtest).status().unwrap();
    assert_eq!((s.blocks, s.version), (120, 290100));
    assert!(matches!(core(&m, Network::Bitcoin).status(), Err(NodeError::WrongChain { .. })));
    let bad = Core::new(
        &NodeConfig {
            rpc_addr: Some(m.addr.clone()),
            user: Some("x".into()),
            password: Some("y".into()),
            ..Default::default()
        },
        Network::Regtest,
    );
    assert!(matches!(bad.status(), Err(NodeError::Rpc(RpcError::Unauthorized))));
}

#[test]
fn import_creates_watch_only_wallet_with_ranged_descriptors() {
    let m = start();
    let w = ModernWallet::restore(Network::Regtest, "t", ABANDON, "", None, 0).unwrap().wallet;
    let r = core(&m, Network::Regtest).import(&w, 100, Rescan::Birthday).unwrap();
    assert!(r.created);
    assert_eq!(r.core_wallet, format!("armory-{}", w.id));
    let calls = m.calls.lock().unwrap();
    let create = calls.iter().find(|c| c.1 == "createwallet").unwrap();
    assert_eq!(create.2[1], json!(true), "private keys disabled");
    let imp = calls.iter().find(|c| c.1 == "importdescriptors").unwrap();
    assert_eq!(imp.0, format!("/wallet/armory-{}", w.id));
    let reqs = imp.2[0].as_array().unwrap();
    assert_eq!(reqs.len(), 2);
    assert!(reqs[0]["desc"].as_str().unwrap().starts_with("wpkh([73c5da0a/84h/1h/0h]tpub"));
    assert_eq!(reqs[0]["range"], json!([0, 99]));
    assert_eq!(reqs[1]["internal"], json!(true));
    assert_eq!(reqs[0]["timestamp"], json!(0), "restored wallets rescan from genesis");
    // Core refused the narrower range; both descriptors are retried with the range it reported.
    let retry = calls.iter().filter(|c| c.1 == "importdescriptors").nth(1).unwrap();
    let reqs = retry.2[0].as_array().unwrap();
    assert_eq!(reqs.len(), 2);
    assert!(reqs.iter().all(|r| r["range"] == json!([0, 999])));
}

#[test]
fn legacy_account_imports_one_descriptor_per_address() {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/legacy/armory_GDHFnMQ2_.wallet");
    let old = armory_wallet::LegacyWallet::parse(&std::fs::read(p).unwrap()).unwrap();
    let mut w = ModernWallet::generate(Network::Testnet, "m", 12, "", None, None, 1_000_000).unwrap().wallet;
    let mut u = w.unlock(None).unwrap();
    w.migrate_legacy(&mut u, &old, None, None).unwrap();
    let reqs = Core::import_requests(&w, 20, Rescan::Now).unwrap();
    // 2 ranged BIP84 descriptors + (11 used + 20 gap) legacy pkh descriptors.
    assert_eq!(reqs.len(), 2 + 31);
    assert!(reqs[2]["desc"].as_str().unwrap().starts_with("pkh(04"));
    assert_eq!(reqs[2]["timestamp"], json!("now"));
    assert_eq!(w.birthday, 1_000_000 - 7200);
}

#[test]
fn balances_history_utxos_fees_broadcast() {
    let m = start();
    let c = core(&m, Network::Regtest);
    assert_eq!(c.balances("x").unwrap(), Balances { confirmed: 150_000_000, pending: 12_345, immature: 0 });
    let h = c.history("x", 10, 0).unwrap();
    assert_eq!(h[0].txid, "bb", "newest first");
    assert_eq!(h[1].amount, 150_000_000);
    assert_eq!(c.utxos("x", 1).unwrap()[0].amount, 150_000_000);
    assert!((c.estimate_fee(6).unwrap() - 12.0).abs() < 1e-9);
    let e = c.estimate_fee(1).unwrap_err().to_string();
    assert!(e.contains("implausible fee estimate"), "{e}");
    assert_eq!(c.broadcast("00").unwrap(), "c0ffee");
    let e = c.broadcast("bad").unwrap_err().to_string();
    assert!(e.contains("min relay fee not met"), "{e}");
}

#[test]
fn fund_psbt_request_shape() {
    let m = start();
    let c = core(&m, Network::Regtest);
    let req = armory_node::core::FundRequest {
        wallet_id: "abcd".into(),
        outputs: vec![("bcrt1qdest".into(), 123_456_789)],
        inputs: vec![],
        change_address: "bcrt1qchange".into(),
        fee_rate: 7.5,
        subtract_fee: false,
    };
    assert_eq!(c.fund_psbt(&req).unwrap(), "cHNidP8=");
    let calls = m.calls.lock().unwrap();
    let f = calls.iter().find(|c| c.1 == "walletcreatefundedpsbt").unwrap();
    assert_eq!(f.0, "/wallet/armory-abcd");
    assert_eq!(f.2[1], json!([{"bcrt1qdest": "1.23456789"}]));
    assert_eq!(f.2[3]["changeAddress"], "bcrt1qchange");
    assert_eq!(f.2[3]["fee_rate"], 7.5);
    assert_eq!(f.2[3]["replaceable"], true);
    assert_eq!(f.2[3]["add_inputs"], true);
}
