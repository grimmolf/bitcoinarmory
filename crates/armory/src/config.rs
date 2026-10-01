//! `armory.toml`: defaults for global options. Precedence: command line > environment
//! (`ARMORY_*`) > config file > built-in default (issue #288).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

/// Settable keys and the command-line option each one provides a default for.
pub const KEYS: &[(&str, &str, &str)] = &[
    ("network", "network", "mainnet, testnet3, testnet4, signet or regtest"),
    ("rpc-addr", "rpc_addr", "Bitcoin Core RPC host:port"),
    ("rpc-cookie", "rpc_cookie", "path of Core's .cookie file"),
    ("rpc-user", "rpc_user", "RPC user (rpcauth setups only)"),
    ("bitcoin-datadir", "bitcoin_datadir", "Bitcoin Core data directory"),
];

/// Where the config file lives: `<datadir>/armory.toml` with `--datadir`, otherwise the
/// platform config directory (`~/.config/armory`, `~/Library/Application Support/Armory`).
pub fn path(datadir: Option<&Path>) -> Option<PathBuf> {
    match datadir {
        Some(d) => Some(d.join("armory.toml")),
        None => directories::ProjectDirs::from("", "", "Armory").map(|p| p.config_dir().join("armory.toml")),
    }
}

pub fn load(path: &Path) -> Result<BTreeMap<String, String>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let table: toml::Table = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(table
        .into_iter()
        .map(|(k, v)| (k, v.as_str().map(String::from).unwrap_or_else(|| v.to_string())))
        .collect())
}

pub fn save(path: &Path, values: &BTreeMap<String, String>) -> Result<()> {
    if let Some(dir) = path.parent() {
        crate::context::create_private_dir(dir)?;
    }
    let table: toml::Table =
        values.iter().map(|(k, v)| (k.clone(), toml::Value::String(v.clone()))).collect();
    armory_wallet::store::atomic_write(path, toml::to_string(&table)?.as_bytes())?;
    Ok(())
}

pub fn check_key(key: &str) -> Result<()> {
    if KEYS.iter().any(|(k, _, _)| *k == key) {
        Ok(())
    } else {
        bail!("unknown setting {key}; known: {}", KEYS.iter().map(|k| k.0).collect::<Vec<_>>().join(", "))
    }
}

/// `--datadir` from the raw arguments or `ARMORY_DATADIR`, needed before parsing to find the file.
pub fn early_datadir(args: &[String]) -> Option<PathBuf> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--datadir" {
            return it.next().map(PathBuf::from);
        }
        if let Some(v) = a.strip_prefix("--datadir=") {
            return Some(PathBuf::from(v));
        }
    }
    std::env::var_os("ARMORY_DATADIR").map(PathBuf::from)
}
