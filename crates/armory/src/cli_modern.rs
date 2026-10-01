//! `armory wallet` and `armory address`: modern (v2) wallets.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail};
use armory_wallet::LegacyWallet;
use armory_wallet::modern::{self, AccountKind, KdfParams, ModernWallet, Unlocked};
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::context::{Context, read_secret};
use crate::{app, print};

#[derive(Subcommand)]
pub enum WalletCmd {
    /// List wallets.
    List,
    /// Show a wallet and its accounts.
    Show { id: String },
    /// Create a wallet with a new BIP39 recovery phrase (BIP84 SegWit account).
    Create(CreateArgs),
    /// Restore a wallet from its BIP39 recovery phrase (read from the prompt or stdin).
    Restore(RestoreArgs),
    /// Move an Armory 0.93 (v1.35) wallet into a modern wallet as a legacy account.
    Migrate(MigrateArgs),
    /// Change the wallet name and description.
    Rename {
        id: String,
        #[arg(long)]
        label: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Set, change or remove the encryption passphrase.
    Passphrase {
        id: String,
        #[arg(value_enum)]
        action: PassAction,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Add a BIP84 (segwit) or BIP86 (taproot) account.
    AddAccount {
        id: String,
        #[arg(value_enum)]
        kind: Kind,
        #[arg(long, default_value_t = 0)]
        index: u32,
    },
    /// Output descriptors for watch-only import (Bitcoin Core `importdescriptors`, other wallets).
    Descriptors {
        id: String,
        #[arg(long)]
        account: Option<usize>,
        /// Include private keys (xprv). Requires the passphrase.
        #[arg(long)]
        private: bool,
        /// Number of addresses to list for legacy accounts.
        #[arg(long, default_value_t = 100)]
        legacy_count: u32,
    },
    /// Verify the wallet: secrets match the public account data, addresses derive.
    Check { id: String },
    /// Show the BIP39 recovery phrase (requires the passphrase).
    ShowSeed { id: String },
    /// Write a copy without any secrets.
    ExportWatchonly { id: String, dest: PathBuf },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PassAction {
    Set,
    Change,
    Remove,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Kind {
    Segwit,
    Taproot,
}

#[derive(Args, Clone)]
pub struct KdfArgs {
    /// Argon2id memory in MiB.
    #[arg(long, default_value_t = 256)]
    kdf_memory_mib: u32,
    /// Argon2id passes.
    #[arg(long, default_value_t = 3)]
    kdf_iterations: u32,
}

impl KdfArgs {
    pub(crate) fn params(&self) -> KdfParams {
        KdfParams::with_cost(self.kdf_memory_mib.max(1) * 1024, self.kdf_iterations.max(1))
    }
}

#[derive(Args)]
pub struct CreateArgs {
    #[arg(long)]
    label: String,
    #[arg(long, default_value = "")]
    description: String,
    /// 12 or 24 recovery words.
    #[arg(long, default_value_t = 24)]
    words: usize,
    /// Also create a BIP86 taproot account.
    #[arg(long)]
    taproot: bool,
    /// Ask for an optional BIP39 passphrase ("25th word").
    #[arg(long)]
    bip39_passphrase: bool,
    /// Store secrets without a passphrase (not recommended).
    #[arg(long)]
    no_encrypt: bool,
    /// Extra entropy (e.g. dice rolls) mixed into the OS random number generator.
    #[arg(long)]
    extra_entropy: Option<String>,
    #[command(flatten)]
    kdf: KdfArgs,
}

#[derive(Args)]
pub struct RestoreArgs {
    #[arg(long, default_value = "Restored")]
    label: String,
    #[arg(long)]
    taproot: bool,
    #[arg(long)]
    bip39_passphrase: bool,
    #[arg(long)]
    no_encrypt: bool,
    #[command(flatten)]
    kdf: KdfArgs,
}

#[derive(Args)]
pub struct MigrateArgs {
    /// Legacy wallet ID (in the data directory) or path to a `.wallet` file.
    legacy: String,
    /// Add to this existing modern wallet instead of creating a new one.
    #[arg(long)]
    into: Option<String>,
    /// Label of the new wallet (default: the legacy wallet's name).
    #[arg(long)]
    label: Option<String>,
    /// File holding the legacy wallet's passphrase.
    #[arg(long)]
    legacy_passphrase_file: Option<PathBuf>,
    #[arg(long, default_value_t = 24)]
    words: usize,
    #[arg(long)]
    no_encrypt: bool,
    #[command(flatten)]
    kdf: KdfArgs,
}

#[derive(Subcommand)]
pub enum AddressCmd {
    /// Get the next unused receive address (never asks for the passphrase).
    New {
        id: String,
        #[arg(long, default_value_t = 0)]
        account: usize,
        /// A change address instead of a receive address.
        #[arg(long)]
        change: bool,
    },
    /// List the addresses handed out so far.
    List {
        id: String,
        #[arg(long)]
        account: Option<usize>,
    },
    /// Set the label of an address.
    Label { address: String, label: String },
}

pub(crate) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub(crate) fn wallets(ctx: &Context) -> Result<Vec<(PathBuf, ModernWallet)>> {
    let mut out = Vec::new();
    for p in modern::discover(&ctx.wallet_dir()?)? {
        match ModernWallet::load(&p) {
            Ok(w) if w.network == ctx.network.bitcoin() => out.push((p, w)),
            Ok(_) => {}
            Err(e) => eprintln!("warning: skipping {}: {e}", p.display()),
        }
    }
    Ok(out)
}

pub(crate) fn open(ctx: &Context, id: &str) -> Result<(PathBuf, ModernWallet)> {
    let mut m: Vec<_> = wallets(ctx)?.into_iter().filter(|(_, w)| w.id.starts_with(id)).collect();
    match m.len() {
        0 => bail!(
            "no wallet with ID {id} on {} (legacy files: `armory legacy wallet list`)",
            ctx.network.dir_name()
        ),
        1 => Ok(m.remove(0)),
        _ => bail!("wallet ID prefix {id} is ambiguous"),
    }
}

pub(crate) fn unlock(ctx: &Context, w: &ModernWallet) -> Result<(Unlocked, Option<Zeroizing<String>>)> {
    if w.is_encrypted() {
        let p = ctx.passphrase(&format!("Passphrase for wallet {}: ", w.id))?;
        let u = w.unlock(Some(p.as_bytes()))?;
        Ok((u, Some(p)))
    } else {
        Ok((w.unlock(None)?, None))
    }
}

pub(crate) fn new_protection(ctx: &Context, no_encrypt: bool) -> Result<Option<Zeroizing<String>>> {
    if no_encrypt { Ok(None) } else { Ok(Some(ctx.new_passphrase()?)) }
}

pub(crate) fn bip39_pass(ask: bool) -> Result<Zeroizing<String>> {
    if ask {
        read_secret("BIP39 passphrase (optional 25th word): ")
    } else {
        Ok(Zeroizing::new(String::new()))
    }
}

pub(crate) fn store_new(ctx: &Context, w: &ModernWallet) -> Result<PathBuf> {
    let path = ctx.wallet_dir()?.join(w.file_name());
    if path.exists() {
        bail!("wallet {} already exists at {}", w.id, path.display());
    }
    w.save(&path)?;
    Ok(path)
}

#[derive(Serialize)]
struct AccountView {
    index: usize,
    kind: AccountKind,
    name: String,
    path: Option<String>,
    xpub: Option<String>,
    legacy_wallet_id: Option<String>,
    next_receive: u32,
    next_change: u32,
}

#[derive(Serialize)]
pub(crate) struct WalletView {
    id: String,
    label: String,
    description: String,
    network: String,
    created: u64,
    protection: &'static str,
    accounts: Vec<AccountView>,
    path: PathBuf,
}

pub(crate) fn view(path: &Path, w: &ModernWallet) -> WalletView {
    WalletView {
        id: w.id.clone(),
        label: w.label.clone(),
        description: w.description.clone(),
        network: w.network.to_string(),
        created: w.created,
        protection: if w.is_watching_only() {
            "watching-only"
        } else if w.is_encrypted() {
            "encrypted"
        } else {
            "unencrypted"
        },
        accounts: w
            .accounts
            .iter()
            .enumerate()
            .map(|(i, a)| AccountView {
                index: i,
                kind: a.kind,
                name: a.name.clone(),
                path: a.path.clone(),
                xpub: a.xpub.clone(),
                legacy_wallet_id: a.legacy.as_ref().map(|l| l.wallet_id.clone()),
                next_receive: a.next_receive,
                next_change: a.next_change,
            })
            .collect(),
        path: path.to_path_buf(),
    }
}

pub(crate) fn view_text(v: &WalletView) -> String {
    let mut s = format!(
        "Wallet ID:   {}\nName:        {}\nNetwork:     {}\nProtection:  {}\nFile:        {}\nAccounts:",
        v.id,
        v.label,
        v.network,
        v.protection,
        v.path.display()
    );
    for a in &v.accounts {
        let detail = a.path.clone().or_else(|| a.legacy_wallet_id.clone()).unwrap_or_default();
        s.push_str(&format!(
            "\n  [{}] {:<28} {:<12} {:<20} receive {} / change {}",
            a.index,
            a.name,
            serde_json::to_value(a.kind).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
            detail,
            a.next_receive,
            a.next_change
        ));
    }
    s
}

#[derive(Serialize)]
pub(crate) struct Created {
    #[serde(flatten)]
    pub(crate) wallet: WalletView,
    pub(crate) mnemonic: String,
}

pub(crate) fn show_mnemonic(json: bool, c: &Created) {
    print(json, c, |c| {
        eprintln!(
            "\nWrite these words down on paper and keep them safe. Anyone with them can spend your funds;\nwithout them (and the passphrase) a lost wallet file cannot be recovered."
        );
        format!("{}\n\nRecovery phrase:\n{}", view_text(&c.wallet), numbered(&c.mnemonic))
    });
}

pub(crate) fn numbered(m: &str) -> String {
    m.split(' ')
        .enumerate()
        .map(|(i, w)| format!("{:>2}. {w:<10}", i + 1))
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn wallet(ctx: &Context, json: bool, cmd: WalletCmd) -> Result<()> {
    let net = ctx.network.bitcoin();
    match cmd {
        WalletCmd::List => {
            let list: Vec<_> = wallets(ctx)?.iter().map(|(p, w)| view(p, w)).collect();
            print(json, &list, |l| {
                if l.is_empty() {
                    return format!(
                        "No wallets on {}. Create one with `armory wallet create --label NAME`, or migrate an Armory 0.93 wallet with `armory wallet migrate`.",
                        ctx.network.dir_name()
                    );
                }
                l.iter()
                    .map(|v| {
                        format!(
                            "{:<10} {:<14} {} account(s)  {}",
                            v.id,
                            v.protection,
                            v.accounts.len(),
                            v.label
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        WalletCmd::Show { id } => {
            let (p, w) = open(ctx, &id)?;
            print(json, &view(&p, &w), view_text);
        }
        WalletCmd::Create(a) => {
            let pass = new_protection(ctx, a.no_encrypt)?;
            let b39 = bip39_pass(a.bip39_passphrase)?;
            let params = a.kdf.params();
            let mut nw = ModernWallet::generate(
                net,
                &a.label,
                a.words,
                &b39,
                pass.as_ref().map(|p| (p.as_bytes(), params)),
                a.extra_entropy.as_deref().map(str::as_bytes),
                now(),
            )?;
            nw.wallet.description = a.description.clone();
            if a.taproot {
                let u = nw.wallet.unlock(pass.as_ref().map(|p| p.as_bytes()))?;
                nw.wallet.add_account(&u, AccountKind::Bip86, 0)?;
            }
            let path = store_new(ctx, &nw.wallet)?;
            show_mnemonic(
                json,
                &Created { wallet: view(&path, &nw.wallet), mnemonic: nw.mnemonic.to_string() },
            );
        }
        WalletCmd::Restore(a) => {
            let words = read_secret("Recovery phrase: ")?;
            let b39 = bip39_pass(a.bip39_passphrase)?;
            let pass = new_protection(ctx, a.no_encrypt)?;
            let params = a.kdf.params();
            let mut nw = ModernWallet::restore(
                net,
                &a.label,
                &words,
                &b39,
                pass.as_ref().map(|p| (p.as_bytes(), params)),
                now(),
            )?;
            if a.taproot {
                let u = nw.wallet.unlock(pass.as_ref().map(|p| p.as_bytes()))?;
                nw.wallet.add_account(&u, AccountKind::Bip86, 0)?;
            }
            let path = store_new(ctx, &nw.wallet)?;
            print(json, &view(&path, &nw.wallet), |v| format!("Restored wallet {}.\n{}", v.id, view_text(v)));
        }
        WalletCmd::Migrate(a) => migrate(ctx, json, a)?,
        WalletCmd::Rename { id, label, description } => {
            let (p, mut w) = open(ctx, &id)?;
            w.label = label;
            w.description = description;
            w.save(&p)?;
            print(json, &view(&p, &w), |v| format!("Wallet {} renamed to {}.", v.id, v.label));
        }
        WalletCmd::Passphrase { id, action, kdf } => {
            let (p, mut w) = open(ctx, &id)?;
            match (action, w.is_encrypted()) {
                (PassAction::Set, true) => bail!("wallet is already encrypted; use `change`"),
                (PassAction::Change | PassAction::Remove, false) => {
                    bail!("wallet is not encrypted; use `set`")
                }
                _ => {}
            }
            let (u, _) = unlock(ctx, &w)?;
            let new = match action {
                PassAction::Remove => None,
                _ => Some(ctx.new_passphrase()?),
            };
            w.reseal(&u, new.as_ref().map(|n| (n.as_bytes(), kdf.params())))?;
            w.save(&p)?;
            print(json, &view(&p, &w), |v| format!("Wallet {} is now {}.", v.id, v.protection));
        }
        WalletCmd::AddAccount { id, kind, index } => {
            let (p, mut w) = open(ctx, &id)?;
            let (u, _) = unlock(ctx, &w)?;
            let k = match kind {
                Kind::Segwit => AccountKind::Bip84,
                Kind::Taproot => AccountKind::Bip86,
            };
            w.add_account(&u, k, index)?;
            w.save(&p)?;
            print(json, &view(&p, &w), view_text);
        }
        WalletCmd::Descriptors { id, account, private, legacy_count } => {
            let (_, w) = open(ctx, &id)?;
            let unlocked = if private { Some(unlock(ctx, &w)?.0) } else { None };
            let mut out = Vec::new();
            for i in 0..w.accounts.len() {
                if account.is_some_and(|a| a != i) {
                    continue;
                }
                let d = match &unlocked {
                    Some(u) if w.accounts[i].kind != AccountKind::Legacy135 => w.private_descriptors(u, i)?,
                    _ => w.public_descriptors(i, legacy_count)?,
                };
                out.extend(d);
            }
            if private {
                eprintln!("WARNING: these descriptors contain private keys.");
            }
            print(json, &out, |o| o.join("\n"));
        }
        WalletCmd::Check { id } => {
            let (_, w) = open(ctx, &id)?;
            let checked_secrets = if w.is_watching_only() {
                false
            } else {
                unlock(ctx, &w)?; // verifies every account against the secrets
                true
            };
            let mut derived = 0;
            for (i, a) in w.accounts.iter().enumerate() {
                let branches: &[u32] = if a.kind == AccountKind::Legacy135 { &[0] } else { &[0, 1] };
                for b in branches {
                    for idx in 0..3 {
                        w.address(i, *b, idx)?;
                        derived += 1;
                    }
                }
            }
            let r = serde_json::json!({ "id": w.id, "secrets_verified": checked_secrets, "addresses_derived": derived });
            print(json, &r, |_| {
                format!(
                    "Wallet {}: OK.{} {derived} sample addresses derived.",
                    w.id,
                    if checked_secrets { " Public data matches the secrets." } else { " Watching-only." }
                )
            });
        }
        WalletCmd::ShowSeed { id } => {
            let (p, w) = open(ctx, &id)?;
            let (u, _) = unlock(ctx, &w)?;
            show_mnemonic(json, &Created { wallet: view(&p, &w), mnemonic: u.mnemonic()?.to_string() });
        }
        WalletCmd::ExportWatchonly { id, dest } => {
            let (_, w) = open(ctx, &id)?;
            let wo = w.watching_only_copy();
            let dest = if dest.is_dir() { dest.join(format!("{}-watchonly.armory", wo.id)) } else { dest };
            if dest.exists() {
                bail!("{} already exists", dest.display());
            }
            armory_wallet::store::atomic_write(&dest, &wo.to_json()?)?;
            print(json, &dest, |d| format!("Watching-only copy written to {}.", d.display()));
        }
    }
    Ok(())
}

pub(crate) fn load_legacy(ctx: &Context, which: &str) -> Result<LegacyWallet> {
    let p = Path::new(which);
    if p.is_file() {
        let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
        return Ok(LegacyWallet::parse(&bytes)?);
    }
    Ok(app::open_wallet(ctx, which)?.wallet)
}

fn migrate(ctx: &Context, json: bool, a: MigrateArgs) -> Result<()> {
    let legacy = load_legacy(ctx, &a.legacy)?;
    let legacy_key = if legacy.is_encrypted() {
        let pass = match &a.legacy_passphrase_file {
            Some(f) => Zeroizing::new(std::fs::read_to_string(f)?.trim_end_matches(['\r', '\n']).to_string()),
            None => read_secret(&format!("Passphrase of legacy wallet {}: ", legacy.id()))?,
        };
        Some(legacy.unlock(pass.as_bytes())?)
    } else {
        None
    };
    let legacy_key = legacy_key.as_deref().map(|k| &k[..]);

    let (path, mut w, mnemonic, pass, unlocked) = match &a.into {
        Some(id) => {
            let (p, w) = open(ctx, id)?;
            let (u, pass) = unlock(ctx, &w)?;
            (p, w, None, pass, Some(u))
        }
        None => {
            let pass = new_protection(ctx, a.no_encrypt)?;
            let label = a.label.clone().unwrap_or_else(|| legacy.label());
            let nw = ModernWallet::generate(
                ctx.network.bitcoin(),
                &label,
                a.words,
                "",
                pass.as_ref().map(|p| (p.as_bytes(), a.kdf.params())),
                None,
                now(),
            )?;
            let path = ctx.wallet_dir()?.join(nw.wallet.file_name());
            (path, nw.wallet, Some(nw.mnemonic), pass, None)
        }
    };
    let mut u = match unlocked {
        Some(u) => u,
        None => w.unlock(pass.as_ref().map(|p| p.as_bytes()))?,
    };
    let acct = w.migrate_legacy(&mut u, &legacy, legacy_key, pass.as_ref().map(|p| p.as_bytes()))?;
    w.save(&path)?;
    let v = view(&path, &w);
    match mnemonic {
        Some(m) => show_mnemonic(json, &Created { wallet: v, mnemonic: m.to_string() }),
        None => print(json, &v, |v| {
            format!("Legacy wallet {} added as account [{acct}].\n{}", legacy.id(), view_text(v))
        }),
    }
    eprintln!(
        "The original file of legacy wallet {} was not changed. Its funds stay on its addresses until you sweep them.",
        legacy.id()
    );
    Ok(())
}

/// Which wallet and account hold an address (searching handed-out addresses).
fn locate(ctx: &Context, address: &str) -> Result<(PathBuf, ModernWallet)> {
    for (p, w) in wallets(ctx)? {
        for (i, a) in w.accounts.iter().enumerate() {
            let branches: &[(u32, u32)] = &[(0, a.next_receive), (1, a.next_change)];
            for (b, n) in branches {
                for idx in 0..*n + 20 {
                    if a.kind == AccountKind::Legacy135 && *b == 1 {
                        break;
                    }
                    if w.address(i, *b, idx)?.to_string() == address {
                        return Ok((p, w));
                    }
                }
            }
        }
    }
    Err(anyhow!("address {address} is not in any wallet"))
}

#[derive(Serialize)]
struct AddrView {
    account: usize,
    branch: &'static str,
    index: u32,
    address: String,
    label: Option<String>,
}

pub fn address(ctx: &Context, json: bool, cmd: AddressCmd) -> Result<()> {
    match cmd {
        AddressCmd::New { id, account, change } => {
            let (p, mut w) = open(ctx, &id)?;
            let a = if change { w.next_change(account)? } else { w.next_receive(account)? };
            w.save(&p)?;
            print(json, &a.to_string(), |a| a.clone());
        }
        AddressCmd::List { id, account } => {
            let (_, w) = open(ctx, &id)?;
            let mut out = Vec::new();
            for (i, a) in w.accounts.iter().enumerate() {
                if account.is_some_and(|x| x != i) {
                    continue;
                }
                for (b, n, name) in [(0, a.next_receive, "receive"), (1, a.next_change, "change")] {
                    for idx in 0..n {
                        let addr = w.address(i, b, idx)?.to_string();
                        out.push(AddrView {
                            account: i,
                            branch: name,
                            index: idx,
                            label: w.address_labels.get(&addr).cloned(),
                            address: addr,
                        });
                    }
                }
            }
            print(json, &out, |o| {
                o.iter()
                    .map(|v| {
                        format!(
                            "[{}] {:<7} {:>4}  {:<64} {}",
                            v.account,
                            v.branch,
                            v.index,
                            v.address,
                            v.label.as_deref().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        AddressCmd::Label { address, label } => {
            let (p, mut w) = locate(ctx, &address)?;
            w.address_labels.insert(address.clone(), label);
            w.save(&p)?;
            print(json, &address, |a| format!("Label set for {a}."));
        }
    }
    Ok(())
}
