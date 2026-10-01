//! `armory`: command-line interface (and, later, the TUI) for Armory wallets.

#[macro_use]
mod io;
mod app;
mod cli_backup;
mod cli_lockbox;
mod cli_message;
mod cli_misc;
mod cli_modern;
mod cli_node;
mod cli_tx;
mod config;
mod context;
mod ops;
mod tui;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::Serialize;

use context::{Context, Network};

#[derive(Parser)]
#[command(
    name = "armory",
    version,
    about = "Armory Bitcoin wallet: cold storage, paper backups, multisig lockboxes",
    long_about = "Armory Bitcoin wallet.\n\nRun `armory tui` for the terminal interface. Settings in armory.toml (see `armory config path`) provide defaults for the global options.",
    propagate_version = true
)]
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
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Full-screen terminal interface (the default when no command is given).
    Tui,
    /// Create, restore, migrate and manage wallets (BIP39 / BIP84 / BIP86).
    #[command(subcommand)]
    Wallet(cli_modern::WalletCmd),
    /// Receive addresses and labels.
    #[command(subcommand)]
    Address(cli_modern::AddressCmd),
    /// Send bitcoin (Core selects coins; Armory signs and broadcasts, or writes a PSBT).
    Send(cli_tx::SendArgs),
    /// Partially signed transactions (PSBT): show, sign offline, broadcast.
    #[command(subcommand)]
    Tx(cli_tx::TxCmd),
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
    /// Multisig lockboxes (SegWit, and imported Armory 0.93 lockboxes).
    #[command(subcommand)]
    Lockbox(cli_lockbox::LockboxCmd),
    /// Address book of people you pay.
    #[command(subcommand)]
    Addressbook(cli_misc::BookCmd),
    /// `bitcoin:` payment request links.
    #[command(subcommand)]
    Uri(cli_misc::UriCmd),
    /// Move all coins of a private key you hold into a wallet.
    Sweep {
        id: String,
        #[command(flatten)]
        fee: cli_tx::FeeArgs,
        #[arg(long, short)]
        yes: bool,
    },
    /// Key and transaction tools.
    #[command(subcommand)]
    Tools(cli_misc::ToolsCmd),
    /// Settings file (defaults for global options).
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Print shell completions (bash, zsh, fish, elvish, powershell).
    Completions { shell: clap_complete::Shell },
    /// Print the manual page (roff).
    Manpage,
    /// About Armory: version, licence, credits.
    About,
    /// Sign and verify messages (BIP137, BIP322, Armory signed blocks).
    #[command(subcommand)]
    Message(cli_message::MessageCmd),
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
        outln!("{}", serde_json::to_string_pretty(value).expect("serializable"));
    } else {
        outln!("{}", text(value));
    }
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Show the settings.
    List,
    /// Set a setting.
    Set { key: String, value: String },
    /// Remove a setting.
    Unset { key: String },
    /// Print the settings file location.
    Path,
}

fn config_cmd(datadir: Option<&std::path::Path>, json: bool, cmd: ConfigCmd) -> Result<()> {
    let path =
        config::path(datadir).ok_or_else(|| anyhow::anyhow!("cannot determine the config directory"))?;
    let mut values = config::load(&path)?;
    match cmd {
        ConfigCmd::List => print(json, &values, |v| {
            let mut out: Vec<String> = config::KEYS
                .iter()
                .map(|(k, _, help)| {
                    format!("{k:<16} = {:<40} # {help}", v.get(*k).map(String::as_str).unwrap_or(""))
                })
                .collect();
            out.insert(0, format!("# {}", path.display()));
            out.join("\n")
        }),
        ConfigCmd::Set { key, value } => {
            config::check_key(&key)?;
            values.insert(key, value);
            config::save(&path, &values)?;
            print(json, &values, |_| "Saved.".into());
        }
        ConfigCmd::Unset { key } => {
            config::check_key(&key)?;
            values.remove(&key);
            config::save(&path, &values)?;
            print(json, &values, |_| "Saved.".into());
        }
        ConfigCmd::Path => print(json, &path, |p| p.display().to_string()),
    }
    Ok(())
}

/// Write to stdout, treating a closed pipe (`| head`) as success.
fn write_stdout(b: &[u8]) -> Result<()> {
    use std::io::Write;
    if io::captured() {
        io::out(&String::from_utf8_lossy(b));
        return Ok(());
    }
    match std::io::stdout().write_all(b) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        r => Ok(r?),
    }
}

fn run(cli: Cli) -> Result<()> {
    let command = match cli.command {
        None | Some(Command::Tui) => {
            if io::captured() {
                anyhow::bail!("the terminal interface is already running");
            }
            let ctx = Context::new(cli.network, cli.datadir.clone(), cli.passphrase_file.clone())?;
            return tui::run(tui::Setup {
                ctx,
                node: cli.node,
                datadir: cli.datadir,
                passphrase_file: cli.passphrase_file,
            });
        }
        Some(c) => c,
    };
    match &command {
        Command::Config(_) | Command::Completions { .. } | Command::Manpage | Command::About => {
            return match command {
                Command::Config(cmd) => config_cmd(cli.datadir.as_deref(), cli.json, cmd),
                Command::Completions { shell } => {
                    let mut buf = Vec::new();
                    clap_complete::generate(shell, &mut Cli::command(), "armory", &mut buf);
                    write_stdout(&buf)
                }
                Command::Manpage => {
                    let mut buf = Vec::new();
                    clap_mangen::Man::new(Cli::command()).render(&mut buf)?;
                    write_stdout(&buf)
                }
                _ => {
                    outln!(
                        "Armory {} (Rust)\nCopyright (C) 2011-2015 Armory Technologies, Inc.; Rust rebuild by the Armory contributors.\nLicensed under the GNU Affero General Public License v3 or later; see LICENSE.\nNo warranty. This program never contacts any server other than your own Bitcoin Core node.",
                        env!("CARGO_PKG_VERSION")
                    );
                    Ok(())
                }
            };
        }
        _ => {}
    }
    let ctx = Context::new(cli.network, cli.datadir, cli.passphrase_file)?;
    let json = cli.json;
    match command {
        Command::Wallet(cli_modern::WalletCmd::Sync(a)) => cli_node::sync(&ctx, &cli.node, json, a),
        Command::Wallet(cli_modern::WalletCmd::SweepLegacy(a)) => {
            cli_tx::sweep_legacy(&ctx, &cli.node, json, a)
        }
        Command::Wallet(cmd) => cli_modern::wallet(&ctx, json, cmd),
        Command::Send(a) => cli_tx::send(&ctx, &cli.node, json, a),
        Command::Tx(cmd) => cli_tx::tx(&ctx, &cli.node, json, cmd),
        Command::Balance { id } => cli_node::balance(&ctx, &cli.node, json, &id),
        Command::History { id, limit, csv } => cli_node::history(&ctx, &cli.node, json, &id, limit, csv),
        Command::Utxos { id, min_conf } => cli_node::utxos(&ctx, &cli.node, json, &id, min_conf),
        Command::Node(cmd) => cli_node::node(&ctx, &cli.node, json, cmd),
        Command::Address(cmd) => cli_modern::address(&ctx, json, cmd),
        Command::Lockbox(cmd) => cli_lockbox::lockbox(&ctx, &cli.node, json, cmd),
        Command::Config(_)
        | Command::Completions { .. }
        | Command::Manpage
        | Command::About
        | Command::Tui => unreachable!(),
        Command::Addressbook(cmd) => cli_misc::addressbook(&ctx, json, cmd),
        Command::Uri(cmd) => cli_misc::uri(&ctx, json, cmd),
        Command::Sweep { id, fee, yes } => cli_misc::sweep_key(&ctx, &cli.node, json, &id, &fee, yes),
        Command::Tools(cmd) => cli_misc::tools(&ctx, json, cmd),
        Command::Message(cmd) => cli_message::message(&ctx, json, cmd),
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
            noteln!("WARNING: anyone who sees this private key can spend the funds of this address.");
            print(json, &k, |k| {
                format!(
                    "Address:     {}\nWIF:         {}\nPrivate key: {}\nPublic key:  {}",
                    k.address, k.wif, k.private_key_hex, k.public_key_hex
                )
            });
        }
        LegacyAddressCmd::ImportKey { id } => {
            let mut f = app::open_wallet(ctx, &id)?;
            let text = io::secret("Private key: ")?;
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

/// Run a command line (without the program name) the way the TUI does: output captured and
/// prompts answered from `inputs`.
pub(crate) fn run_captured(args: &[String], inputs: io::Inputs) -> (Result<()>, zeroize::Zeroizing<String>) {
    io::capture(inputs, || {
        let cli = Cli::try_parse_from(std::iter::once("armory".to_string()).chain(args.iter().cloned()))?;
        run(cli)
    })
}

/// Exit codes: 0 ok, 1 error, 2 usage (clap), 3 wrong passphrase, 4 backup test failed.
/// Parse the command line with armory.toml values as defaults (CLI > env > file > built-in).
fn parse_cli() -> Cli {
    let args: Vec<String> = std::env::args().collect();
    let mut cmd = Cli::command();
    if let Some(path) = config::path(config::early_datadir(&args).as_deref()) {
        match config::load(&path) {
            Ok(values) => {
                for (key, arg_id, _) in config::KEYS {
                    if let Some(v) = values.get(*key) {
                        let v: &'static str = Box::leak(v.clone().into_boxed_str());
                        cmd = cmd.mut_arg(*arg_id, |a| a.default_value(v));
                    }
                }
            }
            Err(e) => eprintln!("warning: ignoring {}: {e:#}", path.display()),
        }
    }
    let matches = cmd.get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

fn main() -> ExitCode {
    let cli = parse_cli();
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
