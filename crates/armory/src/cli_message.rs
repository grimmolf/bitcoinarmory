//! `armory message sign|verify`: BIP137, BIP322 and Armory 0.93 signed blocks.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context as _, Result, anyhow, bail};
use armory_node::core::DEFAULT_GAP;
use armory_wallet::message::{self, CompactKind};
use bitcoin::Address;
use clap::{Args, Subcommand, ValueEnum};

use crate::cli_modern as m;
use crate::context::Context;
use crate::print;

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum SigFormat {
    /// BIP322 for SegWit/Taproot, Bitcoin-Qt (BIP137) for legacy addresses.
    Auto,
    /// Bitcoin-Qt / BIP137 compact signature (P2PKH and P2WPKH).
    Bip137,
    /// BIP322 simple (P2WPKH and P2TR).
    Bip322,
    /// Armory clearsign block (legacy P2PKH addresses), readable by Armory 0.93.
    Clearsign,
}

#[derive(Args)]
pub struct MessageInput {
    /// The message text.
    #[arg(long, conflicts_with = "file")]
    message: Option<String>,
    /// Read the message from a file.
    #[arg(long)]
    file: Option<PathBuf>,
}

impl MessageInput {
    fn text(&self) -> Result<Option<String>> {
        match (&self.message, &self.file) {
            (Some(m), _) => Ok(Some(m.clone())),
            (None, Some(f)) => {
                Ok(Some(std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?))
            }
            (None, None) => Ok(None),
        }
    }
}

#[derive(Subcommand)]
pub enum MessageCmd {
    /// Sign a message with one of your addresses.
    Sign {
        address: String,
        #[command(flatten)]
        input: MessageInput,
        #[arg(long, value_enum, default_value_t = SigFormat::Auto)]
        format: SigFormat,
    },
    /// Verify a signature (or an Armory signed block with --block).
    Verify {
        /// Expected signer (required except for Armory blocks, where the signer is shown).
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        signature: Option<String>,
        #[command(flatten)]
        input: MessageInput,
        /// An Armory "BITCOIN SIGNED MESSAGE" / "BITCOIN MESSAGE" block file (`-`: standard input).
        #[arg(long, conflicts_with_all = ["signature", "message", "file"])]
        block: Option<PathBuf>,
    },
}

pub fn message(ctx: &Context, json: bool, cmd: MessageCmd) -> Result<()> {
    let net = ctx.network.bitcoin();
    match cmd {
        MessageCmd::Sign { address, input, format } => {
            let text = input.text()?.ok_or_else(|| anyhow!("give --message or --file"))?;
            let addr = Address::from_str(&address)?
                .require_network(net)
                .map_err(|_| anyhow!("address is for another network"))?;
            let (path, w) = m::wallets(ctx)?
                .into_iter()
                .find(|(_, w)| w.find_address(&addr, DEFAULT_GAP).is_some())
                .ok_or_else(|| anyhow!("{address} is not in any of your wallets"))?;
            let _ = path;
            let (u, _) = m::unlock(ctx, &w)?;
            let (sk, compressed) = w.key_for_address(&u, &addr, DEFAULT_GAP)?;
            let spk = addr.script_pubkey();
            let fmt = match format {
                SigFormat::Auto if spk.is_p2pkh() => SigFormat::Bip137,
                SigFormat::Auto => SigFormat::Bip322,
                f => f,
            };
            let out = match fmt {
                SigFormat::Bip137 => {
                    let kind = if spk.is_p2wpkh() {
                        CompactKind::P2wpkh
                    } else if spk.is_p2pkh() && compressed {
                        CompactKind::P2pkhCompressed
                    } else if spk.is_p2pkh() {
                        CompactKind::P2pkhUncompressed
                    } else {
                        bail!("BIP137 signatures cover P2PKH and P2WPKH addresses; use --format bip322")
                    };
                    message::sign_compact(&sk, kind, text.as_bytes())
                }
                SigFormat::Bip322 => message::sign_bip322(&sk, &addr, text.as_bytes())?,
                SigFormat::Clearsign => {
                    if !spk.is_p2pkh() {
                        bail!("Armory clearsign blocks are for legacy (P2PKH) addresses");
                    }
                    message::clearsign_block(
                        &sk,
                        compressed,
                        &text,
                        &format!("Signed by Armory {}", env!("CARGO_PKG_VERSION")),
                    )
                }
                SigFormat::Auto => unreachable!(),
            };
            print(json, &serde_json::json!({"address": address, "signature": out}), |_| out.clone());
        }
        MessageCmd::Verify { address, signature, input, block } => {
            if let Some(b) = block {
                let text = if b.as_os_str() == "-" {
                    crate::io::read_all("signed block")?
                } else {
                    std::fs::read_to_string(&b).with_context(|| format!("reading {}", b.display()))?
                };
                let (sig, msg) = message::read_block(&text)?;
                let p2pkh = if net == bitcoin::Network::Bitcoin { 0x00 } else { 0x6f };
                let signer = message::recovered_p2pkh(&sig, msg.as_bytes(), p2pkh)?;
                let ok = address.as_deref().is_none_or(|a| a == signer);
                print(json, &serde_json::json!({"signer": signer, "valid": ok, "message": msg}), |_| {
                    format!(
                        "{}: signed by {signer}\n----- message -----\n{}",
                        if ok { "VALID" } else { "INVALID (different signer)" },
                        msg.replace("\r\n", "\n")
                    )
                });
                if !ok {
                    bail!("the block was not signed by {}", address.unwrap_or_default());
                }
                return Ok(());
            }
            let address = address.ok_or_else(|| anyhow!("--address is required"))?;
            let sig = signature.ok_or_else(|| anyhow!("--signature is required"))?;
            let text = input.text()?.ok_or_else(|| anyhow!("give --message or --file"))?;
            let addr = Address::from_str(&address)?
                .require_network(net)
                .map_err(|_| anyhow!("address is for another network"))?;
            match message::verify(&addr, text.as_bytes(), &sig) {
                Ok(()) => print(json, &serde_json::json!({"valid": true}), |_| {
                    format!("VALID: signed by {address}")
                }),
                Err(e) => {
                    print(json, &serde_json::json!({"valid": false, "reason": e.to_string()}), |_| {
                        format!("INVALID: {e}")
                    });
                    bail!("signature verification failed");
                }
            }
        }
    }
    Ok(())
}
