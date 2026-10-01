//! Spending: `armory send`, `armory tx sign|show|broadcast`, `armory wallet sweep-legacy`.
//!
//! Bitcoin Core (watch-only wallet) selects coins and builds a PSBT; Armory reviews it, signs it
//! with the wallet's keys (optionally on an offline machine) and finalizes it locally.

use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context as _, Result, anyhow, bail};
use armory_node::core::{Core, DEFAULT_GAP, FundRequest, Rescan};
use armory_wallet::modern::{AccountKind, ModernWallet};
use armory_wallet::sign::{self, PsbtSummary};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, Denomination, ScriptBuf};
use clap::{Args, Subcommand};

use crate::cli_modern as m;
use crate::cli_node::NodeArgs;
use crate::context::Context;
use crate::print;

#[derive(Args)]
pub struct FeeArgs {
    /// Fee rate in sat/vB.
    #[arg(long)]
    fee_rate: Option<f64>,
    /// Confirmation target in blocks for Core's fee estimate (default 6).
    #[arg(long, conflicts_with = "fee_rate")]
    target: Option<u16>,
}

#[derive(Args)]
pub struct SendArgs {
    id: String,
    /// Recipient as ADDRESS=BTC (repeatable). With --max: just ADDRESS.
    #[arg(long = "to", required = true)]
    to: Vec<String>,
    /// Send the whole confirmed balance of the account to the single recipient (fee deducted).
    #[arg(long)]
    max: bool,
    /// Account to spend from and to receive change on.
    #[arg(long, default_value_t = 0)]
    account: usize,
    #[command(flatten)]
    fee: FeeArgs,
    /// Write the unsigned PSBT here (for an offline signer) instead of signing.
    #[arg(long)]
    unsigned_out: Option<PathBuf>,
    /// Comment stored with the transaction.
    #[arg(long)]
    comment: Option<String>,
    /// Do not ask for confirmation.
    #[arg(long, short)]
    yes: bool,
}

#[derive(Args)]
pub struct SweepArgs {
    id: String,
    /// Legacy account to sweep (default: every legacy account).
    #[arg(long)]
    from_account: Option<usize>,
    /// Destination account (default 0, the SegWit account).
    #[arg(long, default_value_t = 0)]
    to_account: usize,
    #[command(flatten)]
    fee: FeeArgs,
    #[arg(long)]
    unsigned_out: Option<PathBuf>,
    #[arg(long, short)]
    yes: bool,
}

#[derive(Subcommand)]
pub enum TxCmd {
    /// Show a PSBT file.
    Show {
        file: PathBuf,
        /// Mark outputs that belong to this wallet.
        #[arg(long)]
        wallet: Option<String>,
    },
    /// Sign a PSBT with a wallet (works offline) and write it back (or to --output).
    Sign {
        file: PathBuf,
        #[arg(long)]
        wallet: String,
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Finalize a signed PSBT and broadcast it through Bitcoin Core.
    Broadcast { file: PathBuf },
}

pub fn read_psbt(path: &Path) -> Result<Psbt> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.starts_with(b"psbt\xff") {
        return Ok(Psbt::deserialize(&bytes)?);
    }
    Ok(Psbt::from_str(String::from_utf8_lossy(&bytes).trim())?)
}

fn write_psbt(path: &Path, psbt: &Psbt) -> Result<()> {
    armory_wallet::store::atomic_write(path, format!("{psbt}\n").as_bytes())?;
    Ok(())
}

fn fee_rate(core: &Core, f: &FeeArgs) -> Result<f64> {
    match f.fee_rate {
        Some(r) if r > 0.0 => Ok(r),
        Some(_) => bail!("fee rate must be positive"),
        None => Ok(core.estimate_fee(f.target.unwrap_or(6))?),
    }
}

/// Scripts of every address the wallet has handed out (plus the lookahead), to recognise its outputs.
fn own_scripts(w: &ModernWallet) -> Vec<ScriptBuf> {
    let mut v = Vec::new();
    for (i, a) in w.accounts.iter().enumerate() {
        let branches: &[(u32, u32)] = &[(0, a.next_receive), (1, a.next_change)];
        for (b, n) in branches {
            if a.kind == AccountKind::Legacy135 && *b == 1 {
                continue;
            }
            for idx in 0..n + 20 {
                if let Ok(addr) = w.address(i, *b, idx) {
                    v.push(addr.script_pubkey());
                }
            }
        }
    }
    v
}

fn summary_text(s: &PsbtSummary) -> String {
    let btc = |x: u64| Amount::from_sat(x).to_string_in(Denomination::Bitcoin);
    let mut t = format!("Transaction {}\n  inputs:  {}", s.txid, s.inputs);
    if let Some(total) = s.input_total {
        t.push_str(&format!(" ({} BTC)", btc(total)));
    }
    for (a, v, mine) in &s.outputs {
        t.push_str(&format!(
            "\n  output:  {:>16} BTC  {a}{}",
            btc(*v),
            if *mine { "  (change / own)" } else { "" }
        ));
    }
    if let Some(fee) = s.fee {
        t.push_str(&format!(
            "\n  fee:     {:>16} BTC  (~{:.1} sat/vB)",
            btc(fee),
            fee as f64 / s.vsize_estimate.max(1) as f64
        ));
    }
    t.push_str(&format!(
        "\n  signed:  {}/{} inputs{}",
        s.signed_inputs,
        s.inputs,
        if s.rbf { ", replaceable (RBF)" } else { "" }
    ));
    t
}

fn confirm(yes: bool, question: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("refusing to send without confirmation; pass --yes");
    }
    eprint!("{question} [y/N] ");
    let mut l = String::new();
    std::io::stdin().lock().read_line(&mut l)?;
    if l.trim().eq_ignore_ascii_case("y") || l.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("cancelled")
    }
}

/// Sign, finalize and broadcast (or write the unsigned PSBT); shared by send and sweep.
#[allow(clippy::too_many_arguments)]
fn complete(
    ctx: &Context,
    core: &Core,
    json: bool,
    path: &Path,
    w: &mut ModernWallet,
    mut psbt: Psbt,
    unsigned_out: Option<PathBuf>,
    yes: bool,
    comment: Option<String>,
) -> Result<()> {
    let scripts = own_scripts(w);
    let summary = sign::summarize(&psbt, w.network, &|s| scripts.contains(s));
    if let Some(out) = unsigned_out {
        write_psbt(&out, &psbt)?;
        print(json, &summary, |s| {
            format!("{}\nUnsigned PSBT written to {}.", summary_text(s), out.display())
        });
        return Ok(());
    }
    eprintln!("{}", summary_text(&summary));
    confirm(yes, "Sign and broadcast this transaction?")?;
    let (u, _) = m::unlock(ctx, w)?;
    w.sign_psbt(&u, &mut psbt, DEFAULT_GAP)?;
    sign::finalize(&mut psbt)?;
    let tx = psbt.extract_tx().map_err(|e| anyhow!("cannot extract transaction: {e}"))?;
    let txid = core.broadcast(&serialize_hex(&tx))?;
    if let Some(c) = comment {
        w.tx_comments.insert(txid.clone(), c);
    }
    w.save(path)?;
    print(json, &serde_json::json!({"txid": txid}), |_| format!("Broadcast {txid}"));
    Ok(())
}

pub fn send(ctx: &Context, node: &NodeArgs, json: bool, a: SendArgs) -> Result<()> {
    let (path, mut w) = m::open(ctx, &a.id)?;
    if w.account(a.account)?.kind == AccountKind::Legacy135 {
        bail!(
            "account {} is a legacy account; send from a SegWit/Taproot account or use `wallet sweep-legacy`",
            a.account
        );
    }
    let core = Core::new(&node.config(), w.network);
    core.status()?;
    let mut outputs = Vec::new();
    for t in &a.to {
        let (addr, amt) = match t.split_once('=') {
            Some((x, y)) => (x, Some(y)),
            None => (t.as_str(), None),
        };
        let parsed = Address::from_str(addr.trim())
            .map_err(|e| anyhow!("{addr}: {e}"))?
            .require_network(w.network)
            .map_err(|_| anyhow!("{addr} is not an address for {}", w.network))?;
        let sats = match (amt, a.max) {
            (Some(v), false) => Amount::from_str_in(v.trim(), Denomination::Bitcoin)
                .map_err(|e| anyhow!("{v}: {e}"))?
                .to_sat(),
            (None, true) => 0,
            (Some(_), true) => bail!("with --max give only the address"),
            (None, false) => bail!("missing amount: use ADDRESS=BTC"),
        };
        outputs.push((parsed.to_string(), sats));
    }
    let mut inputs = Vec::new();
    if a.max {
        if outputs.len() != 1 {
            bail!("--max needs exactly one recipient");
        }
        let utxos = core.utxos(&w.id, 1)?;
        if utxos.is_empty() {
            bail!("no confirmed coins to send");
        }
        outputs[0].1 = utxos.iter().map(|u| u.amount as u64).sum();
        inputs = utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect();
    }
    let rate = fee_rate(&core, &a.fee)?;
    // Make sure Core watches the change address we are about to use.
    let change = w.next_change(a.account)?;
    w.save(&path)?;
    core.import(&w, DEFAULT_GAP, Rescan::Now)?;
    let psbt = core.fund_psbt(&FundRequest {
        wallet_id: w.id.clone(),
        outputs,
        inputs,
        change_address: change.to_string(),
        fee_rate: rate,
        subtract_fee: a.max,
    })?;
    let psbt = Psbt::from_str(&psbt)?;
    complete(ctx, &core, json, &path, &mut w, psbt, a.unsigned_out, a.yes, a.comment)
}

pub fn sweep_legacy(ctx: &Context, node: &NodeArgs, json: bool, a: SweepArgs) -> Result<()> {
    let (path, mut w) = m::open(ctx, &a.id)?;
    if w.account(a.to_account)?.kind == AccountKind::Legacy135 {
        bail!("the destination must be a SegWit or Taproot account");
    }
    let mut legacy_scripts = Vec::new();
    for (i, acct) in w.accounts.iter().enumerate() {
        if acct.kind != AccountKind::Legacy135 || a.from_account.is_some_and(|f| f != i) {
            continue;
        }
        for idx in 0..acct.next_receive + DEFAULT_GAP {
            legacy_scripts.push(w.address(i, 0, idx)?.to_string());
        }
    }
    if legacy_scripts.is_empty() {
        bail!("this wallet has no legacy accounts (migrate one with `armory wallet migrate`)");
    }
    let core = Core::new(&node.config(), w.network);
    core.status()?;
    let utxos: Vec<_> = core
        .utxos(&w.id, 1)?
        .into_iter()
        .filter(|u| u.address.as_ref().is_some_and(|a| legacy_scripts.contains(a)))
        .collect();
    if utxos.is_empty() {
        bail!(
            "no confirmed coins on legacy addresses (run `armory wallet sync` if the wallet is new to this node)"
        );
    }
    let total: u64 = utxos.iter().map(|u| u.amount as u64).sum();
    let rate = fee_rate(&core, &a.fee)?;
    let dest = w.next_receive(a.to_account)?;
    w.save(&path)?;
    core.import(&w, DEFAULT_GAP, Rescan::Now)?;
    let psbt = core.fund_psbt(&FundRequest {
        wallet_id: w.id.clone(),
        outputs: vec![(dest.to_string(), total)],
        inputs: utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect(),
        change_address: dest.to_string(),
        fee_rate: rate,
        subtract_fee: true,
    })?;
    let psbt = Psbt::from_str(&psbt)?;
    complete(
        ctx,
        &core,
        json,
        &path,
        &mut w,
        psbt,
        a.unsigned_out,
        a.yes,
        Some("Sweep of Armory 0.93 funds".into()),
    )
}

pub fn tx(ctx: &Context, node: &NodeArgs, json: bool, cmd: TxCmd) -> Result<()> {
    match cmd {
        TxCmd::Show { file, wallet } => {
            let psbt = read_psbt(&file)?;
            let (network, scripts) = match wallet {
                Some(id) => {
                    let (_, w) = m::open(ctx, &id)?;
                    (w.network, own_scripts(&w))
                }
                None => (ctx.network.bitcoin(), Vec::new()),
            };
            let s = sign::summarize(&psbt, network, &|x| scripts.contains(x));
            print(json, &s, summary_text);
        }
        TxCmd::Sign { file, wallet, output } => {
            let (_, w) = m::open(ctx, &wallet)?;
            let mut psbt = read_psbt(&file)?;
            let scripts = own_scripts(&w);
            eprintln!("{}", summary_text(&sign::summarize(&psbt, w.network, &|x| scripts.contains(x))));
            let (u, _) = m::unlock(ctx, &w)?;
            let n = w.sign_psbt(&u, &mut psbt, DEFAULT_GAP)?;
            let out = output.unwrap_or(file);
            write_psbt(&out, &psbt)?;
            print(json, &serde_json::json!({"signed_inputs": n, "file": out}), |_| {
                format!("Signed {n} input(s); wrote {}.", out.display())
            });
        }
        TxCmd::Broadcast { file } => {
            let mut psbt = read_psbt(&file)?;
            sign::finalize(&mut psbt)?;
            let tx = psbt.extract_tx().map_err(|e| anyhow!("cannot extract transaction: {e}"))?;
            let core = Core::new(&node.config(), ctx.network.bitcoin());
            let txid = core.broadcast(&serialize_hex(&tx))?;
            print(json, &serde_json::json!({"txid": txid}), |_| format!("Broadcast {txid}"));
        }
    }
    Ok(())
}
