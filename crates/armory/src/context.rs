//! Global options: network, data directory and passphrase input.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use armory_wallet::LegacyNetwork;
use zeroize::Zeroizing;

/// Bitcoin networks. All test networks share testnet's base58 version bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

impl Network {
    pub fn legacy(self) -> LegacyNetwork {
        match self {
            Network::Mainnet => LegacyNetwork::Mainnet,
            _ => LegacyNetwork::Testnet,
        }
    }

    pub fn bitcoin(self) -> bitcoin::Network {
        match self {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Testnet3 => bitcoin::Network::Testnet,
            Network::Testnet4 => bitcoin::Network::Testnet4,
            Network::Signet => bitcoin::Network::Signet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }

    pub fn dir_name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet3 => "testnet3",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }
}

/// `--datadir`, or the platform data directory.
pub fn data_root(datadir: Option<&Path>) -> Option<PathBuf> {
    match datadir {
        Some(d) => Some(d.to_path_buf()),
        None => directories::ProjectDirs::from("", "", "Armory").map(|p| p.data_dir().to_path_buf()),
    }
}

/// Where Armory keeps its files.
#[derive(Debug, Clone)]
pub struct Context {
    pub network: Network,
    pub data_root: PathBuf,
    passphrase_file: Option<PathBuf>,
}

impl Context {
    pub fn new(network: Network, datadir: Option<PathBuf>, passphrase_file: Option<PathBuf>) -> Result<Self> {
        let data_root =
            data_root(datadir.as_deref()).context("cannot determine the home directory; pass --datadir")?;
        Ok(Self { network, data_root, passphrase_file })
    }

    /// `<data>/<network>/wallets`, created 0700.
    pub fn wallet_dir(&self) -> Result<PathBuf> {
        let net = self.data_root.join(self.network.dir_name());
        create_private_dir(&self.data_root)?;
        create_private_dir(&net)?;
        let d = net.join("wallets");
        create_private_dir(&d)?;
        Ok(d)
    }

    /// Read a passphrase: from `--passphrase-file`, from the terminal (no echo), or as one line of
    /// stdin when stdin is not a terminal.
    pub fn passphrase(&self, prompt: &str) -> Result<Zeroizing<String>> {
        if let Some(p) = &self.passphrase_file {
            let s = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
            return Ok(Zeroizing::new(s.trim_end_matches(['\r', '\n']).to_string()));
        }
        crate::io::secret(prompt)
    }

    /// A new passphrase, asked twice on a terminal.
    pub fn new_passphrase(&self) -> Result<Zeroizing<String>> {
        let p = self.passphrase("New passphrase: ")?;
        if self.passphrase_file.is_none() && !crate::io::captured() && std::io::stdin().is_terminal() {
            let again = self.passphrase("Repeat passphrase: ")?;
            if *again != *p {
                bail!("passphrases do not match");
            }
        }
        if p.is_empty() {
            bail!("empty passphrase");
        }
        Ok(p)
    }
}

/// Read one secret line (see [`crate::io::secret`]).
pub fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
    crate::io::secret(prompt)
}

pub fn create_private_dir(d: &Path) -> Result<()> {
    if !d.exists() {
        std::fs::create_dir_all(d).with_context(|| format!("creating {}", d.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}
