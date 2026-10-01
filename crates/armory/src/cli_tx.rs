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
use armory_wallet::sign::{self, Expected, PsbtSummary};
use armory_wallet::ustx::Ustx;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
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
    pub fee_rate: Option<f64>,
    /// Confirmation target in blocks for Core's fee estimate (default 6).
    #[arg(long, conflicts_with = "fee_rate")]
    pub target: Option<u16>,
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
    /// Account that receives the change (and, with --max, whose coins are sent). Ordinary sends may
    /// use coins of any account of the wallet.
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

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum TxFormat {
    Psbt,
    /// Armory 0.93 TXSIGCOLLECT block.
    Armory,
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
    /// Convert between PSBT and Armory 0.93 offline-transaction (TXSIGCOLLECT) files.
    Convert {
        file: PathBuf,
        #[arg(long, value_enum)]
        to: TxFormat,
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Merge the signatures of several copies of the same PSBT (multisig).
    Combine {
        files: Vec<PathBuf>,
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Finalize a signed PSBT and broadcast it through Bitcoin Core.
    Broadcast { file: PathBuf },
}

/// Read a PSBT (binary or base64) or an Armory 0.93 `TXSIGCOLLECT` file (converted to a PSBT).
/// The flag is true for Armory files.
pub fn read_tx_file(path: &Path, network: bitcoin::Network) -> Result<(Psbt, bool)> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.starts_with(b"psbt\xff") {
        return Ok((Psbt::deserialize(&bytes)?, false));
    }
    let text = String::from_utf8_lossy(&bytes);
    if text.contains("=====TXSIGCOLLECT") {
        return Ok((Ustx::parse(&text, network)?.to_psbt()?, true));
    }
    Ok((Psbt::from_str(text.trim())?, false))
}

pub fn read_psbt(path: &Path, network: bitcoin::Network) -> Result<Psbt> {
    Ok(read_tx_file(path, network)?.0)
}

fn write_ustx(path: &Path, psbt: &Psbt, network: bitcoin::Network) -> Result<()> {
    let block = Ustx::from_psbt(psbt)?.to_block(network);
    armory_wallet::store::atomic_write(path, format!("{block}\n").as_bytes())?;
    Ok(())
}

pub(crate) fn write_psbt(path: &Path, psbt: &Psbt) -> Result<()> {
    armory_wallet::store::atomic_write(path, format!("{psbt}\n").as_bytes())?;
    Ok(())
}

pub(crate) fn fee_rate(core: &Core, f: &FeeArgs) -> Result<f64> {
    match f.fee_rate {
        Some(r) if r > 0.0 => Ok(r),
        Some(_) => bail!("fee rate must be positive"),
        None => Ok(core.estimate_fee(f.target.unwrap_or(6))?),
    }
}

/// Scripts of every address the wallet has handed out (plus the lookahead), to recognise its outputs.
fn own_scripts(w: &ModernWallet) -> Vec<ScriptBuf> {
    (0..w.accounts.len()).flat_map(|i| account_scripts(w, i)).collect()
}

/// Scripts of one account (handed-out addresses plus the lookahead; imported legacy keys too).
fn account_scripts(w: &ModernWallet, i: usize) -> Vec<ScriptBuf> {
    let mut v = Vec::new();
    {
        let a = &w.accounts[i];
        let branches: &[(u32, u32)] = &[(0, a.next_receive), (1, a.next_change)];
        for (b, n) in branches {
            if a.kind == AccountKind::Legacy135 && *b == 1 {
                continue;
            }
            for idx in 0..n + DEFAULT_GAP {
                if let Ok(addr) = w.address(i, *b, idx) {
                    v.push(addr.script_pubkey());
                }
            }
        }
        if let Some(l) = &a.legacy {
            for h in &l.imported_hash160 {
                if let Ok(bytes) = <[u8; 20]>::try_from(
                    (0..20)
                        .map(|k| u8::from_str_radix(&h[2 * k..2 * k + 2], 16).unwrap_or(0))
                        .collect::<Vec<u8>>(),
                ) {
                    v.push(ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array(bytes)));
                }
            }
        }
    }
    v
}

pub(crate) fn summary_text(s: &PsbtSummary) -> String {
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
    if s.signature_status.iter().any(|x| x.contains(" of ")) {
        t.push_str(&format!("\n  status:  {}", s.signature_status.join(", ")));
    }
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

/// What the user asked for; the PSBT from Core is checked against it.
struct Request {
    payments: Vec<(ScriptBuf, u64)>,
    sweep_to: Option<ScriptBuf>,
    fee_rate: f64,
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
    request: Request,
    unsigned_out: Option<PathBuf>,
    yes: bool,
    comment: Option<String>,
) -> Result<()> {
    let scripts = own_scripts(w);
    let summary = sign::summarize(&psbt, w.network, &|s| scripts.contains(s));
    let max_fee = (request.fee_rate * summary.vsize_estimate as f64 * 2.0) as u64 + 1_000;
    sign::check_psbt(
        &psbt,
        &|s| scripts.contains(s),
        &Expected { payments: request.payments, sweep_to: request.sweep_to, max_fee },
    )?;
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
        let acct = account_scripts(&w, a.account);
        let utxos: Vec<_> = core
            .utxos(&w.id, 1)?
            .into_iter()
            .filter(|u| {
                u.address
                    .as_ref()
                    .and_then(|x| Address::from_str(x).ok())
                    .is_some_and(|x| acct.contains(&x.assume_checked().script_pubkey()))
            })
            .collect();
        if utxos.is_empty() {
            bail!("no confirmed coins in account {}", a.account);
        }
        outputs[0].1 = utxos.iter().map(|u| u.amount as u64).sum();
        inputs = utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect();
    }
    let rate = fee_rate(&core, &a.fee)?;
    let request = if a.max {
        Request {
            payments: vec![],
            sweep_to: Some(Address::from_str(&outputs[0].0)?.assume_checked().script_pubkey()),
            fee_rate: rate,
        }
    } else {
        Request {
            payments: outputs
                .iter()
                .map(|(ad, v)| Ok((Address::from_str(ad)?.assume_checked().script_pubkey(), *v)))
                .collect::<Result<Vec<_>>>()?,
            sweep_to: None,
            fee_rate: rate,
        }
    };
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
    complete(ctx, &core, json, &path, &mut w, psbt, request, a.unsigned_out, a.yes, a.comment)
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
        for sc in account_scripts(&w, i) {
            if let Ok(ad) = Address::from_script(&sc, w.network) {
                legacy_scripts.push(ad.to_string());
            }
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
    let request = Request { payments: vec![], sweep_to: Some(dest.script_pubkey()), fee_rate: rate };
    complete(
        ctx,
        &core,
        json,
        &path,
        &mut w,
        psbt,
        request,
        a.unsigned_out,
        a.yes,
        Some("Sweep of Armory 0.93 funds".into()),
    )
}

pub fn tx(ctx: &Context, node: &NodeArgs, json: bool, cmd: TxCmd) -> Result<()> {
    match cmd {
        TxCmd::Show { file, wallet } => {
            let psbt = read_psbt(&file, ctx.network.bitcoin())?;
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
            let (mut psbt, was_ustx) = read_tx_file(&file, ctx.network.bitcoin())?;
            let scripts = own_scripts(&w);
            eprintln!("{}", summary_text(&sign::summarize(&psbt, w.network, &|x| scripts.contains(x))));
            let (u, _) = m::unlock(ctx, &w)?;
            let n = w.sign_psbt(&u, &mut psbt, DEFAULT_GAP)?;
            if n == 0 {
                bail!("wallet {} has no keys for any input of this transaction", w.id);
            }
            let out = output.unwrap_or(file);
            if was_ustx {
                write_ustx(&out, &psbt, w.network)?; // hand an Armory file back in Armory format
            } else {
                write_psbt(&out, &psbt)?;
            }
            print(json, &serde_json::json!({"signed_inputs": n, "file": out}), |_| {
                format!("Signed {n} input(s); wrote {}.", out.display())
            });
        }
        TxCmd::Convert { file, to, output } => {
            let net = ctx.network.bitcoin();
            let psbt = read_psbt(&file, net)?;
            match to {
                TxFormat::Psbt => write_psbt(&output, &psbt)?,
                TxFormat::Armory => write_ustx(&output, &psbt, net)?,
            }
            print(json, &output, |o| format!("Wrote {}.", o.display()));
        }
        TxCmd::Combine { files, output } => {
            let mut it = files.iter();
            let first = it.next().ok_or_else(|| anyhow!("give at least two PSBT files"))?;
            let mut psbt = read_psbt(first, ctx.network.bitcoin())?;
            for f in it {
                psbt.combine(read_psbt(f, ctx.network.bitcoin())?)
                    .map_err(|e| anyhow!("{}: {e}", f.display()))?;
            }
            write_psbt(&output, &psbt)?;
            let s = sign::summarize(&psbt, ctx.network.bitcoin(), &|_| false);
            print(json, &s, |s| {
                format!(
                    "{}
Wrote {}.",
                    summary_text(s),
                    output.display()
                )
            });
        }
        TxCmd::Broadcast { file } => {
            let mut psbt = read_psbt(&file, ctx.network.bitcoin())?;
            sign::finalize(&mut psbt)?;
            let tx = psbt.extract_tx().map_err(|e| anyhow!("cannot extract transaction: {e}"))?;
            let core = Core::new(&node.config(), ctx.network.bitcoin());
            let txid = core.broadcast(&serialize_hex(&tx))?;
            print(json, &serde_json::json!({"txid": txid}), |_| format!("Broadcast {txid}"));
        }
    }
    Ok(())
}
