//! `armory lockbox`: multisig lockboxes (modern BIP48 SegWit and imported Armory 0.93 ones).

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context as _, Result, anyhow, bail};
use armory_node::core::{Core, DEFAULT_GAP, FundRequest, Rescan};
use armory_wallet::lockbox::{self, Lockbox, LockboxKind};
use armory_wallet::sign::{self, Expected};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, Denomination};
use clap::Subcommand;
use serde::Serialize;

use crate::cli_modern as m;
use crate::cli_node::NodeArgs;
use crate::cli_tx::{self, FeeArgs};
use crate::context::Context;
use crate::print;

#[derive(Subcommand)]
pub enum LockboxCmd {
    /// Print this wallet's cosigner key (BIP48) to give to the other lockbox participants.
    ExportKey {
        wallet: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
    },
    /// Create an M-of-N SegWit lockbox from cosigner keys.
    Create {
        #[arg(long)]
        name: String,
        /// Signatures required.
        #[arg(short)]
        m: u8,
        /// Cosigner key `[fingerprint/48h/...]xpub` (repeatable).
        #[arg(long = "key")]
        keys: Vec<String>,
        /// Include one of your wallets as a cosigner.
        #[arg(long = "with-wallet")]
        with_wallets: Vec<String>,
    },
    /// Import lockboxes: a lockbox file from a cosigner, or Armory 0.93 multisigs.txt / LOCKBOX blocks.
    Import { file: PathBuf },
    /// Write a lockbox file to share with the cosigners.
    Export { id: String, dest: PathBuf },
    /// List lockboxes.
    List,
    /// Show a lockbox: keys, address, descriptors.
    Show { id: String },
    /// Next receive address of a lockbox.
    Address { id: String },
    /// Let Bitcoin Core watch the lockbox.
    Sync {
        id: String,
        #[arg(long)]
        no_rescan: bool,
    },
    /// Balance of a lockbox.
    Balance { id: String },
    /// Unspent outputs of a lockbox.
    Utxos { id: String },
    /// Build a spend from the lockbox as a PSBT for the cosigners to sign (`armory tx sign`).
    Spend {
        id: String,
        #[arg(long = "to", required = true)]
        to: Vec<String>,
        #[command(flatten)]
        fee: FeeArgs,
        #[arg(long, short)]
        output: PathBuf,
    },
}

pub(crate) fn lockboxes(ctx: &Context) -> Result<Vec<(PathBuf, Lockbox)>> {
    let mut out = Vec::new();
    let dir = ctx.wallet_dir()?;
    for e in std::fs::read_dir(&dir)? {
        let p = e?.path();
        if p.extension().is_some_and(|x| x == "lockbox") {
            match Lockbox::from_json(&std::fs::read(&p)?) {
                Ok(lb) if lb.network == ctx.network.bitcoin() => out.push((p, lb)),
                Ok(_) => {}
                Err(e) => noteln!("warning: skipping {}: {e}", p.display()),
            }
        }
    }
    out.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    Ok(out)
}

pub(crate) fn open(ctx: &Context, id: &str) -> Result<(PathBuf, Lockbox)> {
    let mut v: Vec<_> = lockboxes(ctx)?.into_iter().filter(|(_, l)| l.id.starts_with(id)).collect();
    match v.len() {
        0 => bail!("no lockbox {id}"),
        1 => Ok(v.remove(0)),
        _ => bail!("lockbox ID prefix {id} is ambiguous"),
    }
}

pub(crate) fn save(path: &Path, lb: &Lockbox) -> Result<()> {
    armory_wallet::store::atomic_write(path, &lb.to_json()?)?;
    Ok(())
}

fn store(ctx: &Context, lb: &Lockbox) -> Result<PathBuf> {
    let p = ctx.wallet_dir()?.join(lb.file_name());
    if p.exists() {
        bail!("lockbox {} already exists", lb.id);
    }
    save(&p, lb)?;
    Ok(p)
}

#[derive(Serialize)]
struct View {
    id: String,
    name: String,
    kind: LockboxKind,
    m: u8,
    n: usize,
    keys: Vec<String>,
    comments: Vec<String>,
    first_address: String,
    descriptors: Vec<String>,
    legacy_id: Option<String>,
}

fn view(lb: &Lockbox) -> Result<View> {
    Ok(View {
        id: lb.id.clone(),
        name: lb.name.clone(),
        kind: lb.kind,
        m: lb.m,
        n: lb.keys.len(),
        keys: lb.keys.clone(),
        comments: lb.key_comments.clone(),
        first_address: lb.address(0, 0)?.to_string(),
        descriptors: lb.descriptors(),
        legacy_id: lb.legacy_id.clone(),
    })
}

fn view_text(v: &View) -> String {
    let mut s = format!(
        "Lockbox {}  \"{}\"  {}-of-{} ({})\nAddress:  {}",
        v.id,
        v.name,
        v.m,
        v.n,
        if v.kind == LockboxKind::WshSortedMulti { "SegWit" } else { "Armory 0.93 P2SH" },
        v.first_address
    );
    for (i, k) in v.keys.iter().enumerate() {
        let c = v.comments.get(i).map(String::as_str).unwrap_or("");
        s.push_str(&format!(
            "\n  key {}: {k}{}",
            i + 1,
            if c.is_empty() { String::new() } else { format!("  ({c})") }
        ));
    }
    for d in &v.descriptors {
        s.push_str(&format!("\n  {d}"));
    }
    s
}

pub fn lockbox(ctx: &Context, node: &NodeArgs, json: bool, cmd: LockboxCmd) -> Result<()> {
    let net = ctx.network.bitcoin();
    match cmd {
        LockboxCmd::ExportKey { wallet, account } => {
            let (_, w) = m::open(ctx, &wallet)?;
            let (u, _) = m::unlock(ctx, &w)?;
            let k = lockbox::cosigner_key(&w, &u, account)?;
            print(json, &k, |k| k.clone());
        }
        LockboxCmd::Create { name, m: need, mut keys, with_wallets } => {
            for id in with_wallets {
                let (_, w) = m::open(ctx, &id)?;
                let (u, _) = m::unlock(ctx, &w)?;
                keys.push(lockbox::cosigner_key(&w, &u, 0)?);
            }
            let lb = Lockbox::new_modern(net, &name, need, keys, vec![], m::now())?;
            store(ctx, &lb)?;
            print(json, &view(&lb)?, |v| {
                format!(
                    "Created {}\nShare it with the cosigners: armory lockbox export {} FILE",
                    view_text(v),
                    v.id
                )
            });
        }
        LockboxCmd::Import { file } => {
            let bytes = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let mut imported = Vec::new();
            if let Ok(lb) = Lockbox::from_json(&bytes) {
                if lb.network != net {
                    bail!("the lockbox is for {}", lb.network);
                }
                store(ctx, &lb)?;
                imported.push(lb.id);
            } else {
                let text = String::from_utf8_lossy(&bytes);
                let legacy = lockbox::read_legacy_lockboxes(&text, net)?;
                if legacy.is_empty() {
                    bail!("no lockboxes found in {}", file.display());
                }
                for l in &legacy {
                    let lb = Lockbox::from_legacy(l, net);
                    if open(ctx, &lb.id).is_ok() {
                        noteln!("lockbox {} already present; skipped", lb.id);
                        continue;
                    }
                    store(ctx, &lb)?;
                    imported.push(lb.id);
                }
            }
            print(json, &imported, |v| format!("Imported lockbox(es): {}", v.join(", ")));
        }
        LockboxCmd::Export { id, dest } => {
            let (_, lb) = open(ctx, &id)?;
            let dest = if dest.is_dir() { dest.join(lb.file_name()) } else { dest };
            save(&dest, &lb)?;
            print(json, &dest, |d| format!("Wrote {}", d.display()));
        }
        LockboxCmd::List => {
            let list: Vec<View> = lockboxes(ctx)?.iter().map(|(_, l)| view(l)).collect::<Result<_>>()?;
            print(json, &list, |l| {
                if l.is_empty() {
                    return "No lockboxes.".into();
                }
                l.iter()
                    .map(|v| format!("{:<10} {}-of-{}  {}  {}", v.id, v.m, v.n, v.first_address, v.name))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        LockboxCmd::Show { id } => {
            let (_, lb) = open(ctx, &id)?;
            print(json, &view(&lb)?, view_text);
        }
        LockboxCmd::Address { id } => {
            let (p, mut lb) = open(ctx, &id)?;
            let a = lb.next_receive()?;
            save(&p, &lb)?;
            print(json, &a.to_string(), |a| a.clone());
        }
        LockboxCmd::Sync { id, no_rescan } => {
            let (_, lb) = open(ctx, &id)?;
            let core = Core::new(&node.config(), net);
            core.status()?;
            let r = core.import_lockbox(
                &lb,
                DEFAULT_GAP,
                if no_rescan { Rescan::Now } else { Rescan::Birthday },
            )?;
            print(json, &r, |r| {
                format!("Lockbox {} is watched by Bitcoin Core wallet '{}'.", lb.id, r.core_wallet)
            });
        }
        LockboxCmd::Balance { id } => {
            let (_, lb) = open(ctx, &id)?;
            let b = Core::new(&node.config(), net).balances(&format!("lb-{}", lb.id))?;
            let btc = |s: i64| Amount::from_sat(s.max(0) as u64).to_string_in(Denomination::Bitcoin);
            print(json, &b, |b| {
                format!(
                    "Lockbox {}\n  confirmed: {} BTC\n  pending:   {} BTC",
                    lb.id,
                    btc(b.confirmed),
                    btc(b.pending)
                )
            });
        }
        LockboxCmd::Utxos { id } => {
            let (_, lb) = open(ctx, &id)?;
            let u = Core::new(&node.config(), net).utxos(&format!("lb-{}", lb.id), 0)?;
            print(json, &u, |u| {
                u.iter()
                    .map(|x| format!("{}:{}  {} sat  {} conf", x.txid, x.vout, x.amount, x.confirmations))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        LockboxCmd::Spend { id, to, fee, output } => {
            let (p, mut lb) = open(ctx, &id)?;
            let core = Core::new(&node.config(), net);
            core.status()?;
            let mut outputs = Vec::new();
            let mut payments = Vec::new();
            for t in &to {
                let (a, v) = t.split_once('=').ok_or_else(|| anyhow!("use ADDRESS=BTC"))?;
                let addr = Address::from_str(a.trim())?
                    .require_network(net)
                    .map_err(|_| anyhow!("{a} is for another network"))?;
                let sats = Amount::from_str_in(v.trim(), Denomination::Bitcoin)?.to_sat();
                payments.push((addr.script_pubkey(), sats));
                outputs.push((addr.to_string(), sats));
            }
            let rate = crate::ops::fee_rate(&core, &fee)?;
            let change = lb.next_change()?;
            save(&p, &lb)?;
            core.import_lockbox(&lb, DEFAULT_GAP, Rescan::Now)?;
            let psbt = core.fund_psbt(&FundRequest {
                wallet_id: format!("lb-{}", lb.id),
                outputs,
                inputs: vec![],
                change_address: change.to_string(),
                fee_rate: rate,
                subtract_fee: false,
            })?;
            let psbt = Psbt::from_str(&psbt)?;
            let scripts = lb.scripts(DEFAULT_GAP);
            let summary = sign::summarize(&psbt, net, &|s| scripts.contains(s));
            let max_fee = crate::ops::max_fee(rate, summary.vsize_estimate);
            sign::check_psbt(
                &psbt,
                &|s| scripts.contains(s),
                &Expected { payments, sweep_to: None, max_fee },
            )?;
            cli_tx::write_psbt(&output, &psbt)?;
            print(json, &summary, |s| {
                format!(
                    "{}\nWrote {}. Each cosigner runs `armory tx sign {} --wallet <ID>`; then `armory tx combine` the signed copies and `armory tx broadcast` the result ({} signatures needed).",
                    cli_tx::summary_text(s),
                    output.display(),
                    output.display(),
                    lb.m
                )
            });
        }
    }
    Ok(())
}
