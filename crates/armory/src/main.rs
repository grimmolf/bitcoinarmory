//! `armory`: command-line interface (and, later, the TUI) for Armory wallets.

mod app;
mod cli_backup;
mod cli_modern;
mod cli_node;
mod context;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use context::{Context, Network};

#[derive(Parser)]
#[command(name = "armory", version, about = "Armory Bitcoin wallet (CLI)", propagate_version = true)]
struct Cli {
    /// Bitcoin network.
    #[arg(long, global = true, value_enum, default_value_t = Network::Mainnet, env = "ARMORY_NETWORK")]
    network: Network,
    /// Keep all Armory data under this directory (portable / air-gapped use).
    #[arg(long, global = true, env = "ARMORY_DATADIR")]
    datadir: Option<PathBuf>,
    /// Read the wallet passphrase from this file instead of prompting.
    #[arg(long, global = true)]
    passphrase_file: Option<PathBuf>,
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,
    #[command(flatten)]
    node: cli_node::NodeArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create, restore, migrate and manage wallets (BIP39 / BIP84 / BIP86).
    #[command(subcommand)]
    Wallet(cli_modern::WalletCmd),
    /// Receive addresses and labels.
    #[command(subcommand)]
    Address(cli_modern::AddressCmd),
    /// Balance of a wallet (from Bitcoin Core; run `wallet sync` first).
    Balance { id: String },
    /// Transaction history (newest first).
    History {
        id: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Write the history as CSV to this file.
        #[arg(long)]
        csv: Option<PathBuf>,
    },
    /// Unspent outputs (coins) of a wallet.
    Utxos {
        id: String,
        #[arg(long, default_value_t = 0)]
        min_conf: u32,
    },
    /// The Bitcoin Core node.
    #[command(subcommand)]
    Node(cli_node::NodeCmd),
    /// Paper, SecurePrint and fragmented backups.
    #[command(subcommand)]
    Backup(cli_backup::BackupCmd),
    /// Restore (or test) a paper or fragmented backup, modern or Armory 0.93.
    #[command(subcommand)]
    Restore(cli_backup::RestoreCmd),
    /// Armory 0.93 (v1.35) `.wallet` files: inspect, keys, byte-compatible edits.
    #[command(subcommand)]
    Legacy(LegacyCmd),
}

#[derive(Subcommand)]
enum LegacyCmd {
    /// Legacy wallet files.
    #[command(subcommand)]
    Wallet(LegacyWalletCmd),
    /// Addresses of legacy wallet files.
    #[command(subcommand)]
    Address(LegacyAddressCmd),
}

#[derive(Subcommand)]
enum LegacyWalletCmd {
    /// List wallets.
    List,
    /// Show wallet properties.
    Show { id: String },
    /// Create a new v1.35 wallet (legacy format; prefer `armory wallet create`).
    Create(CreateArgs),
    /// Import a .wallet file (it is copied, never moved).
    Import {
        file: PathBuf,
        /// Replace an existing wallet with the same ID.
        #[arg(long)]
        replace: bool,
    },
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
        /// Target unlock time for the key-derivation function, in milliseconds.
        #[arg(long, default_value_t = 250)]
        kdf_target_ms: u64,
    },
    /// Verify the key chain (and, with --keys, every private key).
    Check {
        id: String,
        #[arg(long)]
        keys: bool,
    },
    /// Write a watching-only copy (no private keys).
    ExportWatchonly { id: String, dest: PathBuf },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum PassAction {
    Set,
    Change,
    Remove,
}

#[derive(Args)]
struct CreateArgs {
    #[arg(long)]
    label: String,
    #[arg(long, default_value = "")]
    description: String,
    /// Create without a passphrase (not recommended).
    #[arg(long)]
    no_encrypt: bool,
    /// Target unlock time for the key-derivation function, in milliseconds.
    #[arg(long, default_value_t = 250)]
    kdf_target_ms: u64,
    /// Address pool size (default 100 on mainnet, 10 on test networks).
    #[arg(long)]
    pool: Option<usize>,
    /// Extra entropy (e.g. dice rolls) mixed into the OS random number generator.
    #[arg(long)]
    extra_entropy: Option<String>,
}

#[derive(Subcommand)]
enum LegacyAddressCmd {
    /// List the addresses of a wallet.
    List {
        id: String,
        /// Include computed but not yet used addresses.
        #[arg(long)]
        all: bool,
    },
    /// Get the next unused receive address.
    New {
        id: String,
        #[arg(long)]
        pool: Option<usize>,
    },
    /// Show which wallet holds an address.
    Show { address: String },
    /// Set the label of an address.
    Label { address: String, label: String },
    /// Show the private key of an address (requires the passphrase).
    Keys { address: String },
    /// Import a private key (WIF, hex or mini key) read from stdin or the prompt.
    ImportKey { id: String },
    /// Remove an imported address.
    RemoveImported { address: String },
}

pub(crate) fn print<T: Serialize>(json: bool, value: &T, text: impl FnOnce(&T) -> String) {
    if json {
        println!("{}", serde_json::to_string_pretty(value).expect("serializable"));
    } else {
        println!("{}", text(value));
    }
}

fn run(cli: Cli) -> Result<()> {
    let ctx = Context::new(cli.network, cli.datadir, cli.passphrase_file)?;
    let json = cli.json;
    match cli.command {
        Command::Wallet(cli_modern::WalletCmd::Sync(a)) => cli_node::sync(&ctx, &cli.node, json, a),
        Command::Wallet(cmd) => cli_modern::wallet(&ctx, json, cmd),
        Command::Balance { id } => cli_node::balance(&ctx, &cli.node, json, &id),
        Command::History { id, limit, csv } => cli_node::history(&ctx, &cli.node, json, &id, limit, csv),
        Command::Utxos { id, min_conf } => cli_node::utxos(&ctx, &cli.node, json, &id, min_conf),
        Command::Node(cmd) => cli_node::node(&ctx, &cli.node, json, cmd),
        Command::Address(cmd) => cli_modern::address(&ctx, json, cmd),
        Command::Backup(cmd) => cli_backup::backup(&ctx, json, cmd),
        Command::Restore(cmd) => cli_backup::restore(&ctx, json, cmd),
        Command::Legacy(LegacyCmd::Wallet(cmd)) => wallet(&ctx, json, cmd),
        Command::Legacy(LegacyCmd::Address(cmd)) => address(&ctx, json, cmd),
    }
}

fn wallet(ctx: &Context, json: bool, cmd: LegacyWalletCmd) -> Result<()> {
    match cmd {
        LegacyWalletCmd::List => {
            let list: Vec<_> = app::list_wallets(ctx)?.iter().map(app::summary).collect();
            print(json, &list, |l| {
                if l.is_empty() {
                    return format!("No wallets on {}.", ctx.network.dir_name());
                }
                l.iter()
                    .map(|s| {
                        format!(
                            "{:<10} {:<14} {:<10} {}",
                            s.id,
                            s.kind,
                            if s.encrypted { "encrypted" } else { "plain" },
                            s.label
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        LegacyWalletCmd::Show { id } => {
            let f = app::open_wallet(ctx, &id)?;
            print(json, &app::summary(&f), |s| {
                format!(
                    "Wallet ID:      {}\nName:           {}\nDescription:    {}\nType:           {}\nEncrypted:      {}\nCreated:        {}\nAddresses used: {}\nComputed:       {}\nImported keys:  {}\nFile:           {}",
                    s.id,
                    s.label,
                    s.description,
                    s.kind,
                    s.encrypted,
                    s.created,
                    s.highest_used_index + 1,
                    s.last_computed_index + 1,
                    s.imported_keys,
                    s.path.display()
                )
            });
        }
        LegacyWalletCmd::Create(a) => {
            let f = app::create_wallet(
                ctx,
                &app::CreateOptions {
                    label: &a.label,
                    description: &a.description,
                    encrypt: !a.no_encrypt,
                    kdf_target: Duration::from_millis(a.kdf_target_ms),
                    pool: a.pool,
                    extra_entropy: a.extra_entropy.as_deref().map(str::as_bytes),
                },
            )?;
            let s = app::summary(&f);
            print(json, &s, |s| {
                format!("Created legacy wallet {} ({}). Keep a copy of {}.", s.id, s.label, s.path.display())
            });
        }
        LegacyWalletCmd::Import { file, replace } => {
            let f = app::import_wallet(ctx, &file, replace)?;
            print(json, &app::summary(&f), |s| format!("Imported wallet {} ({}).", s.id, s.label));
        }
        LegacyWalletCmd::Rename { id, label, description } => {
            let mut f = app::open_wallet(ctx, &id)?;
            f.wallet.set_labels(&label, &description)?;
            f.save()?;
            print(json, &app::summary(&f), |s| format!("Wallet {} renamed to {}.", s.id, s.label));
        }
        LegacyWalletCmd::Passphrase { id, action, kdf_target_ms } => {
            let mut f = app::open_wallet(ctx, &id)?;
            let what = match action {
                PassAction::Set => app::PassphraseChange::Set,
                PassAction::Change => app::PassphraseChange::Change,
                PassAction::Remove => app::PassphraseChange::Remove,
            };
            app::change_passphrase(ctx, &mut f, what, Duration::from_millis(kdf_target_ms))?;
            print(json, &app::summary(&f), |s| {
                format!("Wallet {} is now {}.", s.id, if s.encrypted { "encrypted" } else { "unencrypted" })
            });
        }
        LegacyWalletCmd::Check { id, keys } => {
            let mut f = app::open_wallet(ctx, &id)?;
            let r = app::check_wallet(ctx, &mut f, keys)?;
            print(json, &r, |r| {
                format!(
                    "Wallet {}: OK. {} chained addresses verified{}.",
                    r.id,
                    r.chained_addresses_verified,
                    if r.private_keys_checked { ", private keys checked" } else { "" }
                )
            });
        }
        LegacyWalletCmd::ExportWatchonly { id, dest } => {
            let f = app::open_wallet(ctx, &id)?;
            let p = app::export_watching_only(&f, &dest)?;
            print(json, &p, |p| format!("Watching-only copy written to {}.", p.display()));
        }
    }
    Ok(())
}

fn address(ctx: &Context, json: bool, cmd: LegacyAddressCmd) -> Result<()> {
    match cmd {
        LegacyAddressCmd::List { id, all } => {
            let f = app::open_wallet(ctx, &id)?;
            let list: Vec<_> =
                app::addresses(&f).into_iter().filter(|a| all || a.used || a.chain_index < 0).collect();
            print(json, &list, |l| {
                l.iter()
                    .map(|a| {
                        let idx =
                            if a.chain_index < 0 { "imp".to_string() } else { a.chain_index.to_string() };
                        format!("{:>5}  {:<36} {}", idx, a.address, a.label.as_deref().unwrap_or(""))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        LegacyAddressCmd::New { id, pool } => {
            let mut f = app::open_wallet(ctx, &id)?;
            let a = app::new_address(&mut f, pool)?;
            print(json, &a, |a| a.address.clone());
        }
        LegacyAddressCmd::Show { address } => {
            let (f, h) = app::find_address(ctx, &address)?;
            let r = f.wallet.record_by_hash160(&h).expect("found");
            let info = serde_json::json!({
                "address": address,
                "wallet": f.wallet.id(),
                "chain_index": r.chain_index,
                "imported": r.is_imported(),
                "has_private_key": r.flags.has_priv,
                "label": f.wallet.address_comments().get(&h),
            });
            print(json, &info, |_| {
                format!(
                    "{address}\n  wallet:      {}\n  chain index: {}\n  label:       {}",
                    f.wallet.id(),
                    if r.is_imported() { "imported".to_string() } else { r.chain_index.to_string() },
                    f.wallet.address_comments().get(&h).map(String::as_str).unwrap_or("")
                )
            });
        }
        LegacyAddressCmd::Label { address, label } => {
            let (mut f, h) = app::find_address(ctx, &address)?;
            app::set_label(&mut f, h, &label)?;
            print(json, &label, |_| format!("Label set for {address}."));
        }
        LegacyAddressCmd::Keys { address } => {
            let (mut f, h) = app::find_address(ctx, &address)?;
            let k = app::export_key(ctx, &mut f, h)?;
            eprintln!("WARNING: anyone who sees this private key can spend the funds of this address.");
            print(json, &k, |k| {
                format!(
                    "Address:     {}\nWIF:         {}\nPrivate key: {}\nPublic key:  {}",
                    k.address, k.wif, k.private_key_hex, k.public_key_hex
                )
            });
        }
        LegacyAddressCmd::ImportKey { id } => {
            let mut f = app::open_wallet(ctx, &id)?;
            let text = context::read_secret("Private key: ")?;
            let a = app::import_key(ctx, &mut f, &text)?;
            print(json, &a, |a| format!("Imported {a}."));
        }
        LegacyAddressCmd::RemoveImported { address } => {
            let (mut f, h) = app::find_address(ctx, &address)?;
            app::remove_imported(&mut f, h)?;
            print(json, &address, |a| format!("Removed {a}."));
        }
    }
    Ok(())
}

/// Exit codes: 0 ok, 1 error, 2 usage (clap), 3 wrong passphrase, 4 backup test failed.
fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            let wrong_pass = matches!(
                e.downcast_ref::<armory_wallet::Error>(),
                Some(armory_wallet::Error::WrongPassphrase)
            ) || matches!(
                e.downcast_ref::<armory_wallet::modern::ModernError>(),
                Some(armory_wallet::modern::ModernError::WrongPassphrase)
            );
            if wrong_pass {
                ExitCode::from(3)
            } else if e.downcast_ref::<cli_backup::TestFailed>().is_some() {
                ExitCode::from(4)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
