//! Spending: `armory send`, `armory tx sign|show|broadcast`, `armory wallet sweep-legacy`.
//!
//! Bitcoin Core (watch-only wallet) selects coins and builds a PSBT; Armory reviews it, signs it
//! with the wallet's keys (optionally on an offline machine) and finalizes it locally.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context as _, Result, anyhow};
use armory_node::core::Core;
use armory_wallet::sign::{self, PsbtSummary};
use armory_wallet::ustx::Ustx;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, Denomination};
use clap::{Args, Subcommand};

use crate::cli_modern as m;
use crate::cli_node::NodeArgs;
use crate::context::Context;
use crate::{ops, print};

#[derive(Args, Clone, Default)]
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
    /// Recipient as ADDRESS=BTC (repeatable). With --max: just ADDRESS. `lockbox:ID=BTC` pays a
    /// lockbox's next deposit address.
    #[arg(long = "to", required_unless_present = "uri")]
    to: Vec<String>,
    /// Pay a `bitcoin:` payment request.
    #[arg(long)]
    uri: Option<String>,
    /// Send the whole confirmed balance of the account to the single recipient (fee deducted).
    #[arg(long)]
    max: bool,
    /// Account that receives the change (and, with --max, whose coins are sent). Ordinary sends may
    /// use coins of any account of the wallet.
    #[arg(long, default_value_t = 0)]
    account: usize,
    /// Coin control: spend exactly these coins, TXID:VOUT (repeatable; see `armory utxos`).
    #[arg(long = "from-utxo")]
    from_utxo: Vec<String>,
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
    /// Replace an unconfirmed transaction with a higher fee (RBF).
    BumpFee {
        wallet: String,
        txid: String,
        /// New fee rate in sat/vB.
        #[arg(long)]
        fee_rate: f64,
        #[arg(long, short)]
        yes: bool,
    },
    /// Forget an unconfirmed transaction that will not confirm (its coins become spendable again).
    Abandon { wallet: String, txid: String },
    /// Attach a comment to a transaction.
    Comment { wallet: String, txid: String, text: String },
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
    /// Finalize a signed PSBT and broadcast it through Bitcoin Core (or a raw transaction, --raw).
    Broadcast {
        #[arg(required_unless_present = "raw")]
        file: Option<PathBuf>,
        /// A fully signed raw transaction in hex.
        #[arg(long, conflicts_with = "file")]
        raw: Option<String>,
    },
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
    for (i, ty) in &s.odd_sighash {
        t.push_str(&format!("\n  WARNING: input {i} requests sighash type {ty:#04x}, not ALL"));
    }
    if s.signature_status.iter().any(|x| x.contains(" of ")) {
        t.push_str(&format!("\n  status:  {}", s.signature_status.join(", ")));
    }
    t
}

pub(crate) fn confirm(yes: bool, question: &str) -> Result<()> {
    crate::io::confirm(yes, question)
}

/// Write the unsigned PSBT, or show it, confirm, unlock, sign and broadcast.
fn complete(
    ctx: &Context,
    core: &Core,
    json: bool,
    p: ops::Prepared,
    unsigned_out: Option<PathBuf>,
    yes: bool,
) -> Result<()> {
    if let Some(out) = unsigned_out {
        write_psbt(&out, &p.psbt)?;
        print(json, &p.summary, |s| {
            format!("{}\nUnsigned PSBT written to {}.", summary_text(s), out.display())
        });
        return Ok(());
    }
    noteln!("{}", summary_text(&p.summary));
    confirm(yes, "Sign and broadcast this transaction?")?;
    let pass = if p.wallet.is_encrypted() {
        Some(ctx.passphrase(&format!("Passphrase for wallet {}: ", p.wallet.id))?)
    } else {
        None
    };
    let txid = ops::execute(ctx, core, p, pass.as_ref().map(|x| x.as_bytes()))?;
    print(json, &serde_json::json!({"txid": txid}), |_| format!("Broadcast {txid}"));
    Ok(())
}

pub fn send(ctx: &Context, node: &NodeArgs, json: bool, mut a: SendArgs) -> Result<()> {
    if let Some(u) = &a.uri {
        let p = crate::cli_misc::PaymentUri::parse(u)?;
        let amt =
            p.amount_sat.ok_or_else(|| anyhow!("the payment request has no amount; use --to ADDRESS=BTC"))?;
        a.to.push(format!("{}={}", p.address, Amount::from_sat(amt).to_string_in(Denomination::Bitcoin)));
        if a.comment.is_none() {
            a.comment = match (p.label, p.message) {
                (Some(l), Some(mg)) => Some(format!("{l}: {mg}")),
                (l, mg) => l.or(mg),
            };
        }
    }
    let (_, w) = m::open(ctx, &a.id)?;
    let core = Core::new(&node.config(), w.network);
    let spec = ops::SendSpec {
        wallet: a.id,
        to: a.to,
        max: a.max,
        account: a.account,
        inputs: a.from_utxo,
        fee: a.fee,
        comment: a.comment,
    };
    let p = ops::prepare_send(ctx, &core, &spec)?;
    complete(ctx, &core, json, p, a.unsigned_out, a.yes)
}

pub fn sweep_legacy(ctx: &Context, node: &NodeArgs, json: bool, a: SweepArgs) -> Result<()> {
    let (_, w) = m::open(ctx, &a.id)?;
    let core = Core::new(&node.config(), w.network);
    let p = ops::prepare_sweep_legacy(ctx, &core, &a.id, a.from_account, a.to_account, &a.fee)?;
    complete(ctx, &core, json, p, a.unsigned_out, a.yes)
}

pub fn tx(ctx: &Context, node: &NodeArgs, json: bool, cmd: TxCmd) -> Result<()> {
    match cmd {
        TxCmd::Show { file, wallet } => {
            let psbt = read_psbt(&file, ctx.network.bitcoin())?;
            let (network, scripts) = match wallet {
                Some(id) => {
                    let (_, w) = m::open(ctx, &id)?;
                    (w.network, ops::own_scripts(&w))
                }
                None => (ctx.network.bitcoin(), Vec::new()),
            };
            let s = sign::summarize(&psbt, network, &|x| scripts.contains(x));
            print(json, &s, summary_text);
        }
        TxCmd::Sign { file, wallet, output } => {
            let (_, w) = m::open(ctx, &wallet)?;
            let (mut psbt, was_ustx) = read_tx_file(&file, ctx.network.bitcoin())?;
            let scripts = ops::own_scripts(&w);
            noteln!("{}", summary_text(&sign::summarize(&psbt, w.network, &|x| scripts.contains(x))));
            let pass = if w.is_encrypted() {
                Some(ctx.passphrase(&format!("Passphrase for wallet {}: ", w.id))?)
            } else {
                None
            };
            let n = ops::sign_offline(&w, &mut psbt, pass.as_ref().map(|x| x.as_bytes()))?;
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
        TxCmd::BumpFee { wallet, txid, fee_rate, yes } => {
            let (_, w) = m::open(ctx, &wallet)?;
            let core = Core::new(&node.config(), w.network);
            let p = ops::prepare_bump(ctx, &core, &wallet, &txid, fee_rate)?;
            complete(ctx, &core, json, p, None, yes)?;
        }
        TxCmd::Abandon { wallet, txid } => {
            let (_, w) = m::open(ctx, &wallet)?;
            Core::new(&node.config(), w.network).abandon(&w.id, &txid)?;
            print(json, &txid, |t| format!("Abandoned {t}; its inputs are spendable again."));
        }
        TxCmd::Comment { wallet, txid, text } => {
            let (path, mut w) = m::open(ctx, &wallet)?;
            w.tx_comments.insert(txid.clone(), text);
            w.save(&path)?;
            print(json, &txid, |t| format!("Comment saved for {t}."));
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
        TxCmd::Broadcast { file, raw } => {
            let core = Core::new(&node.config(), ctx.network.bitcoin());
            let txid = match (file, raw) {
                (_, Some(hex)) => {
                    let hex: String = hex.split_whitespace().collect();
                    let _: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&hex)
                        .map_err(|e| anyhow!("not a raw transaction: {e}"))?;
                    core.broadcast(&hex)?
                }
                (Some(f), None) => ops::broadcast_psbt(&core, read_psbt(&f, ctx.network.bitcoin())?)?,
                (None, None) => unreachable!("clap requires one"),
            };
            print(json, &serde_json::json!({"txid": txid}), |_| format!("Broadcast {txid}"));
        }
    }
    Ok(())
}
