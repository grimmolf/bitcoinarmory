//! Commands that talk to Bitcoin Core: node status, wallet sync, balance, history, UTXOs.

use std::path::PathBuf;

use anyhow::Result;
use armory_node::core::{Core, DEFAULT_GAP, NodeConfig, RECOMMENDED_VERSION, Rescan};
use clap::{Args, Subcommand};

use crate::cli_modern as m;
use crate::context::Context;
use crate::print;

/// How to reach Bitcoin Core (defaults: local node, cookie authentication).
#[derive(Args, Clone, Default)]
pub struct NodeArgs {
    /// Core RPC address, `host:port` (default 127.0.0.1 and the network's RPC port).
    #[arg(long, global = true, env = "ARMORY_RPC_ADDR")]
    pub rpc_addr: Option<String>,
    /// Core's `.cookie` file (default: in the Bitcoin data directory).
    #[arg(long, global = true, env = "ARMORY_RPC_COOKIE")]
    pub rpc_cookie: Option<PathBuf>,
    /// RPC user (only with `rpcauth`; cookie authentication is preferred).
    #[arg(long, global = true, env = "ARMORY_RPC_USER")]
    pub rpc_user: Option<String>,
    #[arg(long, global = true, env = "ARMORY_RPC_PASSWORD", hide_env_values = true)]
    pub rpc_password: Option<String>,
    /// Bitcoin Core data directory (default ~/.bitcoin or ~/Library/Application Support/Bitcoin).
    #[arg(long, global = true, env = "ARMORY_BITCOIN_DATADIR")]
    pub bitcoin_datadir: Option<PathBuf>,
}

impl NodeArgs {
    pub fn config(&self) -> NodeConfig {
        NodeConfig {
            rpc_addr: self.rpc_addr.clone(),
            cookie_file: self.rpc_cookie.clone(),
            user: self.rpc_user.clone(),
            password: self.rpc_password.clone(),
            bitcoin_datadir: self.bitcoin_datadir.clone(),
        }
    }
}

#[derive(Subcommand)]
pub enum NodeCmd {
    /// Show the connected Bitcoin Core node.
    Status,
}

#[derive(Args)]
pub struct SyncArgs {
    pub id: String,
    /// Addresses watched beyond the last one handed out.
    #[arg(long, default_value_t = DEFAULT_GAP)]
    pub gap: u32,
    /// Rescan from this unix time instead of the wallet birthday.
    #[arg(long)]
    pub rescan_from: Option<u64>,
    /// Do not rescan (only new transactions are seen).
    #[arg(long, conflicts_with = "rescan_from")]
    pub no_rescan: bool,
}

fn btc(sats: i64) -> String {
    let sign = if sats < 0 { "-" } else { "" };
    let a = sats.unsigned_abs();
    format!("{sign}{}.{:08}", a / 100_000_000, a % 100_000_000)
}

fn core(ctx: &Context, node: &NodeArgs) -> Core {
    Core::new(&node.config(), ctx.network.bitcoin())
}

pub fn node(ctx: &Context, node: &NodeArgs, json: bool, cmd: NodeCmd) -> Result<()> {
    match cmd {
        NodeCmd::Status => {
            let s = core(ctx, node).status()?;
            print(json, &s, |s| {
                let mut t = format!(
                    "Bitcoin Core {} on {}\nBlocks:   {} / {} headers ({:.2}% verified){}{}",
                    s.subversion,
                    s.chain,
                    s.blocks,
                    s.headers,
                    s.verification_progress * 100.0,
                    if s.initial_block_download { "\nStill syncing (initial block download)." } else { "" },
                    if s.pruned {
                        "\nPruned node: restoring old wallets needs an unpruned node."
                    } else {
                        ""
                    }
                );
                if s.version < RECOMMENDED_VERSION {
                    t.push_str("\nWarning: this Core release is end-of-life; 29.0 or newer is recommended.");
                }
                t
            });
        }
    }
    Ok(())
}

pub fn sync(ctx: &Context, node: &NodeArgs, json: bool, a: SyncArgs) -> Result<()> {
    let (_, w) = m::open(ctx, &a.id)?;
    let c = core(ctx, node);
    c.status()?;
    let rescan = match (a.no_rescan, a.rescan_from) {
        (true, _) => Rescan::Now,
        (_, Some(t)) => Rescan::From(t),
        _ => Rescan::Birthday,
    };
    if matches!(rescan, Rescan::Birthday) && w.birthday == 0 {
        eprintln!(
            "Rescanning from the genesis block (the wallet's creation date is unknown); this can take a while."
        );
    }
    let r = c.import(&w, a.gap, rescan)?;
    print(json, &r, |r| {
        format!(
            "Wallet {} is watched by Bitcoin Core wallet '{}'{} ({} descriptors).",
            w.id,
            r.core_wallet,
            if r.created { " (created)" } else { "" },
            r.descriptors
        )
    });
    Ok(())
}

pub fn balance(ctx: &Context, node: &NodeArgs, json: bool, id: &str) -> Result<()> {
    let (_, w) = m::open(ctx, id)?;
    let b = core(ctx, node).balances(&w.id)?;
    print(json, &b, |b| {
        format!(
            "Wallet {}\n  confirmed: {} BTC\n  pending:   {} BTC\n  immature:  {} BTC",
            w.id,
            btc(b.confirmed),
            btc(b.pending),
            btc(b.immature)
        )
    });
    Ok(())
}

pub fn history(
    ctx: &Context,
    node: &NodeArgs,
    json: bool,
    id: &str,
    limit: usize,
    csv: Option<PathBuf>,
) -> Result<()> {
    let (_, w) = m::open(ctx, id)?;
    let h = core(ctx, node).history(&w.id, limit, 0)?;
    if let Some(path) = csv {
        let mut out =
            String::from("time,txid,category,amount_btc,fee_btc,confirmations,address,label,comment\n");
        let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        for t in &h {
            let addr = t.address.clone().unwrap_or_default();
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{}\n",
                t.time,
                t.txid,
                t.category,
                btc(t.amount),
                t.fee.map(btc).unwrap_or_default(),
                t.confirmations,
                addr,
                q(w.address_labels.get(&addr).map(String::as_str).unwrap_or("")),
                q(w.tx_comments.get(&t.txid).map(String::as_str).unwrap_or(""))
            ));
        }
        armory_wallet::store::atomic_write(&path, out.as_bytes())?;
        eprintln!("Wrote {} transactions to {}.", h.len(), path.display());
        return Ok(());
    }
    print(json, &h, |h| {
        if h.is_empty() {
            return "No transactions yet (run `armory wallet sync` first).".into();
        }
        h.iter()
            .map(|t| {
                format!(
                    "{:>6} conf  {:>16} BTC  {:<8} {}  {}",
                    t.confirmations,
                    btc(t.amount),
                    t.category,
                    t.txid,
                    t.address
                        .as_deref()
                        .and_then(|a| w.address_labels.get(a))
                        .map(String::as_str)
                        .unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    Ok(())
}

pub fn utxos(ctx: &Context, node: &NodeArgs, json: bool, id: &str, min_conf: u32) -> Result<()> {
    let (_, w) = m::open(ctx, id)?;
    let u = core(ctx, node).utxos(&w.id, min_conf)?;
    print(json, &u, |u| {
        u.iter()
            .map(|x| {
                format!(
                    "{}:{}  {:>16} BTC  {:>6} conf  {}",
                    x.txid,
                    x.vout,
                    btc(x.amount),
                    x.confirmations,
                    x.address.as_deref().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn btc_format() {
        assert_eq!(super::btc(150_000_000), "1.50000000");
        assert_eq!(super::btc(-12_345), "-0.00012345");
    }
}
