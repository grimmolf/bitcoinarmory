//! Operations shared by the command line and the terminal UI.
//!
//! Nothing here prompts or prints: multi-step actions are split into `prepare_*` (build and check a
//! transaction) and [`execute`] (sign with a passphrase the caller obtained, then broadcast), so each
//! frontend supplies its own confirmation and passphrase entry.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Result, anyhow, bail};
use armory_node::core::{Core, DEFAULT_GAP, FundRequest, Rescan};
use armory_wallet::modern::{AccountKind, ModernWallet, Unlocked};
use armory_wallet::sign::{self, Expected, PsbtSummary};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, Denomination, ScriptBuf};

use crate::cli_modern as m;
use crate::cli_tx::FeeArgs;
use crate::context::Context;

/// Scripts of every address the wallet has handed out (plus the lookahead), to recognise its outputs.
pub(crate) fn own_scripts(w: &ModernWallet) -> Vec<ScriptBuf> {
    (0..w.accounts.len()).flat_map(|i| account_scripts(w, i)).collect()
}

/// Scripts of one account (handed-out addresses plus the lookahead; imported legacy keys too).
pub(crate) fn account_scripts(w: &ModernWallet, i: usize) -> Vec<ScriptBuf> {
    let mut v = Vec::new();
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
                    .map(|k| u8::from_str_radix(h.get(2 * k..2 * k + 2).unwrap_or("00"), 16).unwrap_or(0))
                    .collect::<Vec<u8>>(),
            ) {
                v.push(ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array(bytes)));
            }
        }
    }
    v
}

pub(crate) fn fee_rate(core: &Core, f: &FeeArgs) -> Result<f64> {
    match f.fee_rate {
        Some(r) if r > 0.0 => Ok(r),
        Some(_) => bail!("fee rate must be positive"),
        None => Ok(core.estimate_fee(f.target.unwrap_or(6))?),
    }
}

/// What the user asked for; the PSBT from Core is checked against it.
pub(crate) struct Request {
    pub payments: Vec<(ScriptBuf, u64)>,
    pub sweep_to: Option<ScriptBuf>,
    pub fee_rate: f64,
}

/// A checked, unsigned transaction waiting for the user's confirmation.
pub(crate) struct Prepared {
    pub path: PathBuf,
    pub wallet: ModernWallet,
    pub psbt: Psbt,
    pub summary: PsbtSummary,
    pub comment: Option<String>,
    /// Recipient addresses recorded in the address book once broadcast.
    pub recipients: Vec<String>,
}

/// Check a PSBT from Core against the request and summarise it.
pub(crate) fn check(w: &ModernWallet, psbt: &Psbt, request: Request) -> Result<PsbtSummary> {
    let scripts = own_scripts(w);
    let summary = sign::summarize(psbt, w.network, &|s| scripts.contains(s));
    let max_fee = (request.fee_rate * summary.vsize_estimate as f64 * 2.0) as u64 + 1_000;
    sign::check_psbt(
        psbt,
        &|s| scripts.contains(s),
        &Expected { payments: request.payments, sweep_to: request.sweep_to, max_fee },
    )?;
    Ok(summary)
}

/// A payment to make.
#[derive(Clone)]
pub(crate) struct SendSpec {
    pub wallet: String,
    /// `ADDRESS=BTC`, or just `ADDRESS` with `max`.
    pub to: Vec<String>,
    pub max: bool,
    pub account: usize,
    /// Coin control: spend exactly these coins (`TXID:VOUT`).
    pub inputs: Vec<String>,
    pub fee: FeeArgs,
    pub comment: Option<String>,
}

/// Replace `lockbox:ID[=BTC]` recipients by the lockbox's next deposit address.
pub(crate) fn resolve_lockboxes(ctx: &Context, to: &[String]) -> Result<Vec<String>> {
    to.iter()
        .map(|t| match t.strip_prefix("lockbox:") {
            Some(rest) => {
                let (id, amt) = match rest.split_once('=') {
                    Some((i, a)) => (i, Some(a)),
                    None => (rest, None),
                };
                let (path, mut lb) = crate::cli_lockbox::open(ctx, id.trim())?;
                let addr = lb.next_receive()?;
                crate::cli_lockbox::save(&path, &lb)?;
                Ok(match amt {
                    Some(a) => format!("{addr}={a}"),
                    None => addr.to_string(),
                })
            }
            None => Ok(t.clone()),
        })
        .collect()
}

/// Parse `ADDRESS=BTC` recipients for a network.
pub(crate) fn parse_recipients(
    to: &[String],
    max: bool,
    network: bitcoin::Network,
) -> Result<Vec<(String, u64)>> {
    let mut outputs = Vec::new();
    for t in to {
        let (addr, amt) = match t.split_once('=') {
            Some((x, y)) => (x, Some(y)),
            None => (t.as_str(), None),
        };
        let parsed = Address::from_str(addr.trim())
            .map_err(|e| anyhow!("{addr}: {e}"))?
            .require_network(network)
            .map_err(|_| anyhow!("{addr} is not an address for {network}"))?;
        let sats = match (amt, max) {
            (Some(v), false) => {
                let a =
                    Amount::from_str_in(v.trim(), Denomination::Bitcoin).map_err(|e| anyhow!("{v}: {e}"))?;
                if a == Amount::ZERO {
                    bail!("{addr}: amount must be positive");
                }
                a.to_sat()
            }
            (None, true) => 0,
            (Some(_), true) => bail!("with --max give only the address"),
            (None, false) => bail!("missing amount: use ADDRESS=BTC"),
        };
        outputs.push((parsed.to_string(), sats));
    }
    if outputs.is_empty() {
        bail!("no recipient");
    }
    Ok(outputs)
}

/// Build (through Core) and check a payment.
pub(crate) fn prepare_send(ctx: &Context, core: &Core, s: &SendSpec) -> Result<Prepared> {
    let (path, mut w) = m::open(ctx, &s.wallet)?;
    if w.account(s.account)?.kind == AccountKind::Legacy135 {
        bail!(
            "account {} is a legacy account; send from a SegWit/Taproot account or use `wallet sweep-legacy`",
            s.account
        );
    }
    core.status()?;
    let to = resolve_lockboxes(ctx, &s.to)?;
    let mut outputs = parse_recipients(&to, s.max, w.network)?;
    let recipients = outputs.iter().map(|o| o.0.clone()).collect();
    let mut inputs = Vec::new();
    if !s.inputs.is_empty() {
        let coins = core.utxos(&w.id, 0)?;
        let mut total = 0u64;
        for c in &s.inputs {
            let (txid, vout) = c
                .split_once(':')
                .and_then(|(t, v)| Some((t.to_string(), v.parse::<u32>().ok()?)))
                .ok_or_else(|| anyhow!("{c}: expected TXID:VOUT"))?;
            let coin = coins
                .iter()
                .find(|u| u.txid == txid && u.vout == vout)
                .ok_or_else(|| anyhow!("{c} is not an unspent coin of wallet {}", w.id))?;
            total += coin.amount as u64;
            inputs.push((txid, vout));
        }
        if s.max {
            if outputs.len() != 1 {
                bail!("--max needs exactly one recipient");
            }
            outputs[0].1 = total;
        }
    } else if s.max {
        if outputs.len() != 1 {
            bail!("--max needs exactly one recipient");
        }
        let acct = account_scripts(&w, s.account);
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
            bail!("no confirmed coins in account {}", s.account);
        }
        outputs[0].1 = utxos.iter().map(|u| u.amount as u64).sum();
        inputs = utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect();
    }
    let rate = fee_rate(core, &s.fee)?;
    let request = if s.max {
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
    let change = w.next_change(s.account)?;
    w.save(&path)?;
    core.import(&w, DEFAULT_GAP, Rescan::Now)?;
    let psbt = core.fund_psbt(&FundRequest {
        wallet_id: w.id.clone(),
        outputs,
        inputs,
        change_address: change.to_string(),
        fee_rate: rate,
        subtract_fee: s.max,
    })?;
    let psbt = Psbt::from_str(&psbt)?;
    let summary = check(&w, &psbt, request)?;
    Ok(Prepared { path, wallet: w, psbt, summary, comment: s.comment.clone(), recipients })
}

/// Move the coins of migrated legacy accounts into a SegWit/Taproot account.
pub(crate) fn prepare_sweep_legacy(
    ctx: &Context,
    core: &Core,
    id: &str,
    from_account: Option<usize>,
    to_account: usize,
    fee: &FeeArgs,
) -> Result<Prepared> {
    let (path, mut w) = m::open(ctx, id)?;
    if w.account(to_account)?.kind == AccountKind::Legacy135 {
        bail!("the destination must be a SegWit or Taproot account");
    }
    let mut legacy_addrs = Vec::new();
    for (i, acct) in w.accounts.iter().enumerate() {
        if acct.kind != AccountKind::Legacy135 || from_account.is_some_and(|f| f != i) {
            continue;
        }
        for sc in account_scripts(&w, i) {
            if let Ok(ad) = Address::from_script(&sc, w.network) {
                legacy_addrs.push(ad.to_string());
            }
        }
    }
    if legacy_addrs.is_empty() {
        bail!("this wallet has no legacy accounts (migrate one with `armory wallet migrate`)");
    }
    core.status()?;
    let utxos: Vec<_> = core
        .utxos(&w.id, 1)?
        .into_iter()
        .filter(|u| u.address.as_ref().is_some_and(|a| legacy_addrs.contains(a)))
        .collect();
    if utxos.is_empty() {
        bail!(
            "no confirmed coins on legacy addresses (run `armory wallet sync` if the wallet is new to this node)"
        );
    }
    let total: u64 = utxos.iter().map(|u| u.amount as u64).sum();
    let rate = fee_rate(core, fee)?;
    let dest = w.next_receive(to_account)?;
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
    let summary = check(&w, &psbt, request)?;
    Ok(Prepared {
        path,
        wallet: w,
        psbt,
        summary,
        comment: Some("Sweep of Armory 0.93 funds".into()),
        recipients: vec![],
    })
}

/// Replace an unconfirmed transaction with a higher-fee version (RBF).
pub(crate) fn prepare_bump(
    ctx: &Context,
    core: &Core,
    id: &str,
    txid: &str,
    fee_rate: f64,
) -> Result<Prepared> {
    let (path, w) = m::open(ctx, id)?;
    let original: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize_hex(&core.wallet_tx_hex(&w.id, txid)?)?;
    let scripts = own_scripts(&w);
    let payments: Vec<(ScriptBuf, u64)> = original
        .output
        .iter()
        .filter(|o| !scripts.contains(&o.script_pubkey))
        .map(|o| (o.script_pubkey.clone(), o.value.to_sat()))
        .collect();
    let psbt = Psbt::from_str(&core.bump_fee_psbt(&w.id, txid, fee_rate)?)?;
    let summary = check(&w, &psbt, Request { payments, sweep_to: None, fee_rate })?;
    Ok(Prepared {
        path,
        wallet: w,
        psbt,
        summary,
        comment: Some(format!("Fee bump of {txid}")),
        recipients: vec![],
    })
}

/// Sign, finalize and broadcast a prepared transaction; returns the txid.
pub(crate) fn execute(ctx: &Context, core: &Core, p: Prepared, passphrase: Option<&[u8]>) -> Result<String> {
    let u = p.wallet.unlock(passphrase)?;
    execute_unlocked(ctx, core, p, &u)
}

/// [`execute`] with an already unlocked wallet.
pub(crate) fn execute_unlocked(ctx: &Context, core: &Core, p: Prepared, u: &Unlocked) -> Result<String> {
    let Prepared { path, mut wallet, mut psbt, comment, recipients, .. } = p;
    wallet.sign_psbt(u, &mut psbt, DEFAULT_GAP)?;
    sign::finalize(&mut psbt)?;
    let tx = psbt.extract_tx().map_err(|e| anyhow!("cannot extract transaction: {e}"))?;
    let txid = core.broadcast(&serialize_hex(&tx))?;
    if let Some(c) = comment {
        wallet.tx_comments.insert(txid.clone(), c);
    }
    wallet.save(&path)?;
    for r in recipients {
        crate::cli_misc::AddressBook::note_sent(ctx, &r)?;
    }
    Ok(txid)
}

/// Sign a PSBT with a wallet (offline signing). Returns the number of inputs signed.
pub(crate) fn sign_offline(w: &ModernWallet, psbt: &mut Psbt, passphrase: Option<&[u8]>) -> Result<usize> {
    let u = w.unlock(passphrase)?;
    let n = w.sign_psbt(&u, psbt, DEFAULT_GAP)?;
    if n == 0 {
        bail!("wallet {} has no keys for any input of this transaction", w.id);
    }
    Ok(n)
}

/// Finalize a fully signed PSBT and broadcast it.
pub(crate) fn broadcast_psbt(core: &Core, mut psbt: Psbt) -> Result<String> {
    sign::finalize(&mut psbt)?;
    let tx = psbt.extract_tx().map_err(|e| anyhow!("cannot extract transaction: {e}"))?;
    Ok(core.broadcast(&serialize_hex(&tx))?)
}
