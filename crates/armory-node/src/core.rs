//! Bitcoin Core as Armory's blockchain backend (spec 05 §4.2).
//!
//! Every Armory wallet is mirrored into a watch-only descriptor wallet in Core named
//! `armory-<id>` (private keys disabled). Core then tracks balances, history and UTXOs; Armory
//! never parses block files or speaks P2P.

use std::path::PathBuf;

use armory_wallet::modern::{AccountKind, ModernWallet};
use bitcoin::Network;
use serde::Serialize;
use serde_json::{Value, json};

use crate::rpc::{Auth, RpcClient, RpcError};

/// Core 0.21 introduced descriptor wallets; older versions cannot work.
pub const MIN_VERSION: u64 = 210000;
/// Supported floor (older releases are end-of-life).
pub const RECOMMENDED_VERSION: u64 = 290000;
/// Addresses imported beyond the last one handed out.
pub const DEFAULT_GAP: u32 = 100;

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("Bitcoin Core {0} is too old: descriptor wallets need 0.21 or newer (29 or newer recommended)")]
    TooOld(String),
    #[error("Bitcoin Core is on {node}, but Armory is set to {armory}")]
    WrongChain { node: String, armory: String },
    #[error("unexpected response from Bitcoin Core: {0}")]
    Unexpected(String),
    #[error(transparent)]
    Wallet(#[from] armory_wallet::modern::ModernError),
}

pub type Result<T> = std::result::Result<T, NodeError>;

/// Core's chain name for a network (`getblockchaininfo.chain`).
pub fn chain_name(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "main",
        Network::Testnet => "test",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        _ => "regtest",
    }
}

/// Data-directory subfolder Core uses for a network.
pub fn net_subdir(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "",
        Network::Testnet => "testnet3",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        _ => "regtest",
    }
}

pub fn default_rpc_port(n: Network) -> u16 {
    match n {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Testnet4 => 48332,
        Network::Signet => 38332,
        _ => 18443,
    }
}

/// Core's default data directory: `~/.bitcoin` (Linux) or `~/Library/Application Support/Bitcoin`.
pub fn default_bitcoin_datadir() -> Option<PathBuf> {
    let home = directories::BaseDirs::new()?;
    if cfg!(target_os = "macos") {
        Some(home.home_dir().join("Library/Application Support/Bitcoin"))
    } else {
        Some(home.home_dir().join(".bitcoin"))
    }
}

/// How to reach the node. Unset fields use Core's defaults for the network.
#[derive(Debug, Clone, Default)]
pub struct NodeConfig {
    pub rpc_addr: Option<String>,
    pub cookie_file: Option<PathBuf>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub bitcoin_datadir: Option<PathBuf>,
}

impl NodeConfig {
    pub fn client(&self, network: Network) -> RpcClient {
        let addr =
            self.rpc_addr.clone().unwrap_or_else(|| format!("127.0.0.1:{}", default_rpc_port(network)));
        let auth = match (&self.user, &self.password) {
            (Some(u), Some(p)) => Auth::UserPass(u.clone(), p.clone()),
            _ => {
                let cookie = self.cookie_file.clone().unwrap_or_else(|| {
                    let base =
                        self.bitcoin_datadir.clone().or_else(default_bitcoin_datadir).unwrap_or_default();
                    base.join(net_subdir(network)).join(".cookie")
                });
                Auth::Cookie(cookie)
            }
        };
        RpcClient::new(addr, auth)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    pub verification_progress: f64,
    pub initial_block_download: bool,
    pub pruned: bool,
    pub version: u64,
    pub subversion: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Balances {
    pub confirmed: i64,
    pub pending: i64,
    pub immature: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TxEntry {
    pub txid: String,
    pub category: String,
    pub amount: i64,
    pub fee: Option<i64>,
    pub confirmations: i64,
    pub time: u64,
    pub address: Option<String>,
    pub vout: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub address: Option<String>,
    pub amount: i64,
    pub confirmations: i64,
    pub descriptor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub core_wallet: String,
    pub created: bool,
    pub descriptors: usize,
    pub rescan_from: u64,
}

/// An unspent output found by [`Core::scan_utxos`].
#[derive(Debug, Clone, Serialize)]
pub struct ScannedUtxo {
    pub txid: String,
    pub vout: u32,
    pub script_pubkey: String,
    pub amount: i64,
}

/// Parameters for [`Core::fund_psbt`].
#[derive(Debug, Clone)]
pub struct FundRequest {
    pub wallet_id: String,
    pub outputs: Vec<(String, u64)>,
    pub inputs: Vec<(String, u32)>,
    pub change_address: String,
    pub fee_rate: f64,
    pub subtract_fee: bool,
}

/// Satoshis as a BTC decimal string (exact, unlike a float).
pub fn format_btc(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

/// Rescan start for an import.
#[derive(Debug, Clone, Copy)]
pub enum Rescan {
    /// From the wallet birthday (0 = genesis).
    Birthday,
    /// Addresses cannot have history yet (lookahead extension): no rescan.
    Now,
    /// From this unix time.
    From(u64),
}

/// BTC amount (JSON number) to satoshis.
pub fn sats(v: &Value) -> i64 {
    v.as_f64().map(|b| (b * 1e8).round() as i64).unwrap_or(0)
}

pub struct Core {
    pub rpc: RpcClient,
    pub network: Network,
}

impl Core {
    pub fn new(config: &NodeConfig, network: Network) -> Self {
        Self { rpc: config.client(network), network }
    }

    /// Node health; fails if the node is too old or on another chain.
    pub fn status(&self) -> Result<NodeStatus> {
        let bc = self.rpc.call(None, "getblockchaininfo", json!([]))?;
        let ni = self.rpc.call(None, "getnetworkinfo", json!([]))?;
        let s = NodeStatus {
            chain: bc["chain"].as_str().unwrap_or("").to_string(),
            blocks: bc["blocks"].as_u64().unwrap_or(0),
            headers: bc["headers"].as_u64().unwrap_or(0),
            verification_progress: bc["verificationprogress"].as_f64().unwrap_or(0.0),
            initial_block_download: bc["initialblockdownload"].as_bool().unwrap_or(false),
            pruned: bc["pruned"].as_bool().unwrap_or(false),
            version: ni["version"].as_u64().unwrap_or(0),
            subversion: ni["subversion"].as_str().unwrap_or("").to_string(),
        };
        if s.version < MIN_VERSION {
            return Err(NodeError::TooOld(s.subversion));
        }
        if s.chain != chain_name(self.network) {
            return Err(NodeError::WrongChain { node: s.chain, armory: chain_name(self.network).into() });
        }
        Ok(s)
    }

    pub fn wallet_name(id: &str) -> String {
        format!("armory-{id}")
    }

    /// Load the Core watch-only wallet for `id`, creating it if needed. Returns true if created.
    pub fn ensure_wallet(&self, id: &str) -> Result<bool> {
        let name = Self::wallet_name(id);
        let loaded = self.rpc.call(None, "listwallets", json!([]))?;
        if loaded.as_array().is_some_and(|a| a.iter().any(|w| w.as_str() == Some(name.as_str()))) {
            return Ok(false);
        }
        match self.rpc.call(None, "loadwallet", json!([name])) {
            Ok(_) => Ok(false),
            // -18: wallet not found -> create it.
            Err(RpcError::Core { code: -18, .. }) => {
                // createwallet name disable_private_keys blank passphrase avoid_reuse descriptors load_on_startup
                self.rpc.call(None, "createwallet", json!([name, true, true, "", false, true, true]))?;
                Ok(true)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Descriptor import requests for a wallet.
    pub fn import_requests(w: &ModernWallet, gap: u32, rescan: Rescan) -> Result<Vec<Value>> {
        let ts = match rescan {
            Rescan::Birthday => json!(w.birthday),
            Rescan::Now => json!("now"),
            Rescan::From(t) => json!(t),
        };
        let mut reqs = Vec::new();
        for (i, a) in w.accounts.iter().enumerate() {
            match a.kind {
                AccountKind::Bip84 | AccountKind::Bip86 => {
                    let descs = w.public_descriptors(i, 0)?;
                    for (branch, d) in descs.into_iter().enumerate() {
                        let next = if branch == 0 { a.next_receive } else { a.next_change };
                        reqs.push(json!({
                            "desc": d,
                            "range": [0, next + gap - 1],
                            "timestamp": ts,
                            "internal": branch == 1,
                            "active": false,
                        }));
                    }
                }
                AccountKind::Legacy135 => {
                    for d in w.public_descriptors(i, a.next_receive + gap)? {
                        reqs.push(json!({ "desc": d, "timestamp": ts }));
                    }
                }
            }
        }
        Ok(reqs)
    }

    /// Watch a lockbox in Core (`armory-lb-<id>`).
    pub fn import_lockbox(
        &self,
        lb: &armory_wallet::lockbox::Lockbox,
        gap: u32,
        rescan: Rescan,
    ) -> Result<ImportReport> {
        let id = format!("lb-{}", lb.id);
        let created = self.ensure_wallet(&id)?;
        let ts = match rescan {
            Rescan::Birthday => json!(lb.birthday),
            Rescan::Now => json!("now"),
            Rescan::From(t) => json!(t),
        };
        let reqs: Vec<Value> = lb
            .descriptors()
            .into_iter()
            .enumerate()
            .map(|(b, d)| match lb.kind {
                armory_wallet::lockbox::LockboxKind::WshSortedMulti => {
                    let next = if b == 0 { lb.next_receive } else { lb.next_change };
                    json!({"desc": d, "range": [0, next + gap - 1], "timestamp": ts, "internal": b == 1, "active": false})
                }
                armory_wallet::lockbox::LockboxKind::LegacyP2sh => json!({"desc": d, "timestamp": ts}),
            })
            .collect();
        let name = Self::wallet_name(&id);
        self.import_descriptors(&name, reqs.clone())?;
        Ok(ImportReport { core_wallet: name, created, descriptors: reqs.len(), rescan_from: lb.birthday })
    }

    /// Run `importdescriptors`. Core tops up ranged descriptors on its own (to its keypool size) and
    /// refuses a re-import whose range is narrower than what it already watches, so such requests are
    /// widened to the range Core reports and retried.
    fn import_descriptors(&self, wallet: &str, mut reqs: Vec<Value>) -> Result<()> {
        for _ in 0..3 {
            let res = self.rpc.call(Some(wallet), "importdescriptors", json!([reqs]))?;
            let results = res.as_array().ok_or_else(|| NodeError::Unexpected("importdescriptors".into()))?;
            let mut retry = Vec::new();
            for (req, r) in reqs.iter().zip(results) {
                if r["success"] == json!(true) {
                    continue;
                }
                let msg = r["error"]["message"].as_str().unwrap_or("");
                match current_range_end(msg) {
                    Some(end) if req.get("range").is_some() => {
                        let mut req = req.clone();
                        req["range"] = json!([0, end]);
                        retry.push(req);
                    }
                    _ => {
                        return Err(NodeError::Unexpected(format!(
                            "importdescriptors failed: {}",
                            r["error"]
                        )));
                    }
                }
            }
            if retry.is_empty() {
                return Ok(());
            }
            reqs = retry;
        }
        Err(NodeError::Unexpected("importdescriptors: range negotiation did not converge".into()))
    }

    /// Mirror the wallet's descriptors into Core (creating the watch-only wallet if needed).
    pub fn import(&self, w: &ModernWallet, gap: u32, rescan: Rescan) -> Result<ImportReport> {
        let created = self.ensure_wallet(&w.id)?;
        let reqs = Self::import_requests(w, gap, rescan)?;
        let name = Self::wallet_name(&w.id);
        self.import_descriptors(&name, reqs.clone())?;
        Ok(ImportReport {
            core_wallet: name,
            created,
            descriptors: reqs.len(),
            rescan_from: match rescan {
                Rescan::Birthday => w.birthday,
                Rescan::Now => u64::MAX,
                Rescan::From(t) => t,
            },
        })
    }

    pub fn balances(&self, id: &str) -> Result<Balances> {
        let b = self.rpc.call(Some(&Self::wallet_name(id)), "getbalances", json!([]))?;
        // With private keys disabled the watched funds are reported under "mine".
        let m = &b["mine"];
        Ok(Balances {
            confirmed: sats(&m["trusted"]),
            pending: sats(&m["untrusted_pending"]),
            immature: sats(&m["immature"]),
        })
    }

    pub fn history(&self, id: &str, count: usize, skip: usize) -> Result<Vec<TxEntry>> {
        let v = self.rpc.call(
            Some(&Self::wallet_name(id)),
            "listtransactions",
            json!(["*", count, skip, true]),
        )?;
        let arr = v.as_array().ok_or_else(|| NodeError::Unexpected("listtransactions".into()))?;
        let mut out: Vec<TxEntry> = arr
            .iter()
            .map(|t| TxEntry {
                txid: t["txid"].as_str().unwrap_or("").into(),
                category: t["category"].as_str().unwrap_or("").into(),
                amount: sats(&t["amount"]),
                fee: t.get("fee").map(sats),
                confirmations: t["confirmations"].as_i64().unwrap_or(0),
                time: t["time"].as_u64().unwrap_or(0),
                address: t["address"].as_str().map(String::from),
                vout: t["vout"].as_u64().map(|v| v as u32),
            })
            .collect();
        out.reverse(); // newest first
        Ok(out)
    }

    pub fn utxos(&self, id: &str, min_conf: u32) -> Result<Vec<Utxo>> {
        let v = self.rpc.call(Some(&Self::wallet_name(id)), "listunspent", json!([min_conf]))?;
        let arr = v.as_array().ok_or_else(|| NodeError::Unexpected("listunspent".into()))?;
        Ok(arr
            .iter()
            .map(|u| Utxo {
                txid: u["txid"].as_str().unwrap_or("").into(),
                vout: u["vout"].as_u64().unwrap_or(0) as u32,
                address: u["address"].as_str().map(String::from),
                amount: sats(&u["amount"]),
                confirmations: u["confirmations"].as_i64().unwrap_or(0),
                descriptor: u["desc"].as_str().map(String::from),
            })
            .collect())
    }

    /// Fee rate in sat/vB for confirmation within `target` blocks, never below the relay fee.
    pub fn estimate_fee(&self, target: u16) -> Result<f64> {
        let e = self.rpc.call(None, "estimatesmartfee", json!([target]))?;
        let ni = self.rpc.call(None, "getnetworkinfo", json!([]))?;
        let floor = ni["relayfee"].as_f64().unwrap_or(0.00001) * 1e5; // BTC/kvB -> sat/vB
        let est = e["feerate"].as_f64().map(|r| r * 1e5);
        Ok(est.unwrap_or(floor).max(floor))
    }

    /// Let Core choose coins and build a PSBT (`walletcreatefundedpsbt` on the watch-only wallet).
    ///
    /// * `outputs`: address -> satoshis;
    /// * `inputs`: spend exactly these outpoints (no others are added) when given;
    /// * `subtract_fee`: take the fee out of the first output (send-max and sweeps);
    /// * `fee_rate`: sat/vB. RBF is always signalled.
    pub fn fund_psbt(&self, req: &FundRequest) -> Result<String> {
        let outputs: Vec<Value> =
            req.outputs.iter().map(|(a, s)| json!({ a.clone(): format_btc(*s) })).collect();
        let inputs: Vec<Value> = req.inputs.iter().map(|(t, v)| json!({"txid": t, "vout": v})).collect();
        let mut options = json!({
            "changeAddress": req.change_address,
            "fee_rate": req.fee_rate,
            "replaceable": true,
            "includeWatching": true,
            "add_inputs": req.inputs.is_empty(),
        });
        if req.subtract_fee {
            options["subtractFeeFromOutputs"] = json!([0]);
        }
        let r = self.rpc.call(
            Some(&Self::wallet_name(&req.wallet_id)),
            "walletcreatefundedpsbt",
            json!([inputs, outputs, 0, options, true]),
        )?;
        r["psbt"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| NodeError::Unexpected("walletcreatefundedpsbt".into()))
    }

    /// RBF: a PSBT that replaces `txid` at a higher fee rate (`psbtbumpfee` on the watch-only wallet).
    pub fn bump_fee_psbt(&self, wallet_id: &str, txid: &str, fee_rate: f64) -> Result<String> {
        let r = self.rpc.call(
            Some(&Self::wallet_name(wallet_id)),
            "psbtbumpfee",
            json!([txid, {"fee_rate": fee_rate}]),
        )?;
        r["psbt"].as_str().map(String::from).ok_or_else(|| NodeError::Unexpected("psbtbumpfee".into()))
    }

    /// Raw hex of a wallet transaction (`gettransaction`).
    pub fn wallet_tx_hex(&self, wallet_id: &str, txid: &str) -> Result<String> {
        let r = self.rpc.call(Some(&Self::wallet_name(wallet_id)), "gettransaction", json!([txid, true]))?;
        r["hex"].as_str().map(String::from).ok_or_else(|| NodeError::Unexpected("gettransaction".into()))
    }

    /// Forget an unconfirmed transaction that will never confirm (`abandontransaction`).
    pub fn abandon(&self, wallet_id: &str, txid: &str) -> Result<()> {
        self.rpc.call(Some(&Self::wallet_name(wallet_id)), "abandontransaction", json!([txid]))?;
        Ok(())
    }

    /// Unspent outputs of arbitrary descriptors from the UTXO set (`scantxoutset`), without a
    /// wallet or rescan; used to sweep private keys.
    pub fn scan_utxos(&self, descriptors: &[String]) -> Result<Vec<ScannedUtxo>> {
        let r = self.rpc.call(None, "scantxoutset", json!(["start", descriptors]))?;
        let arr = r["unspents"].as_array().ok_or_else(|| NodeError::Unexpected("scantxoutset".into()))?;
        Ok(arr
            .iter()
            .map(|u| ScannedUtxo {
                txid: u["txid"].as_str().unwrap_or("").into(),
                vout: u["vout"].as_u64().unwrap_or(0) as u32,
                script_pubkey: u["scriptPubKey"].as_str().unwrap_or("").into(),
                amount: sats(&u["amount"]),
            })
            .collect())
    }

    /// `testmempoolaccept` then `sendrawtransaction`; Core's reject reason is returned verbatim.
    pub fn broadcast(&self, raw_hex: &str) -> Result<String> {
        let t = self.rpc.call(None, "testmempoolaccept", json!([[raw_hex]]))?;
        let r = &t[0];
        if r["allowed"] != json!(true) {
            return Err(NodeError::Unexpected(format!(
                "transaction rejected: {}",
                r["reject-reason"].as_str().unwrap_or("unknown reason")
            )));
        }
        Ok(self.rpc.call(None, "sendrawtransaction", json!([raw_hex]))?.as_str().unwrap_or("").to_string())
    }
}

/// Parse Core's "new range must include current range = [0,N]" error.
fn current_range_end(msg: &str) -> Option<u64> {
    let rest = msg.split("current range = [").nth(1)?;
    let inner = rest.split(']').next()?;
    inner.split(',').nth(1)?.trim().parse().ok()
}
