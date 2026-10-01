//! Address book, `bitcoin:` URIs, QR codes, private-key sweeps and small tools.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Result, anyhow, bail};
use armory_node::core::Core;
use armory_wallet::sweep::{self, SweepInput, SweepKey};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Address, Amount, Denomination, OutPoint, ScriptBuf, Txid};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

use crate::cli_modern as m;
use crate::cli_node::NodeArgs;
use crate::cli_tx::FeeArgs;
use crate::context::{Context, read_secret};
use crate::print;

// ------------------------------------------------------------------ address book

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressBook {
    pub entries: Vec<BookEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookEntry {
    pub address: String,
    pub label: String,
    #[serde(default)]
    pub times_sent: u32,
}

impl AddressBook {
    fn path(ctx: &Context) -> Result<PathBuf> {
        Ok(ctx.wallet_dir()?.parent().unwrap().join("addressbook.json"))
    }

    pub fn load(ctx: &Context) -> Result<Self> {
        let p = Self::path(ctx)?;
        if !p.exists() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_slice(&std::fs::read(p)?)?)
    }

    pub fn save(&self, ctx: &Context) -> Result<()> {
        armory_wallet::store::atomic_write(&Self::path(ctx)?, &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Record a payment to `address` (sent-to history).
    pub fn note_sent(ctx: &Context, address: &str) -> Result<()> {
        let mut b = Self::load(ctx)?;
        match b.entries.iter_mut().find(|e| e.address == address) {
            Some(e) => e.times_sent += 1,
            None => {
                b.entries.push(BookEntry { address: address.into(), label: String::new(), times_sent: 1 })
            }
        }
        b.save(ctx)
    }
}

#[derive(Subcommand)]
pub enum BookCmd {
    /// List saved and previously paid addresses.
    List,
    /// Add or relabel an address.
    Add { address: String, label: String },
    /// Remove an address.
    Remove { address: String },
}

pub fn addressbook(ctx: &Context, json: bool, cmd: BookCmd) -> Result<()> {
    let mut b = AddressBook::load(ctx)?;
    match cmd {
        BookCmd::List => print(json, &b.entries, |e| {
            if e.is_empty() {
                return "The address book is empty.".into();
            }
            e.iter()
                .map(|x| format!("{:<64} {:<24} sent {}x", x.address, x.label, x.times_sent))
                .collect::<Vec<_>>()
                .join("\n")
        }),
        BookCmd::Add { address, label } => {
            Address::from_str(&address)?
                .require_network(ctx.network.bitcoin())
                .map_err(|_| anyhow!("{address} is not an address for this network"))?;
            match b.entries.iter_mut().find(|e| e.address == address) {
                Some(e) => e.label = label,
                None => b.entries.push(BookEntry { address: address.clone(), label, times_sent: 0 }),
            }
            b.save(ctx)?;
            print(json, &address, |a| format!("Saved {a}."));
        }
        BookCmd::Remove { address } => {
            let n = b.entries.len();
            b.entries.retain(|e| e.address != address);
            if b.entries.len() == n {
                bail!("{address} is not in the address book");
            }
            b.save(ctx)?;
            print(json, &address, |a| format!("Removed {a}."));
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ BIP21 URIs

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PaymentUri {
    pub address: String,
    pub amount_sat: Option<u64>,
    pub label: Option<String>,
    pub message: Option<String>,
}

fn pct_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn pct_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3])?, 16)?);
            i += 3;
        } else if b[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

impl PaymentUri {
    pub fn to_uri(&self) -> String {
        let mut q = Vec::new();
        if let Some(a) = self.amount_sat {
            q.push(format!("amount={}", Amount::from_sat(a).to_string_in(Denomination::Bitcoin)));
        }
        if let Some(l) = &self.label {
            q.push(format!("label={}", pct_encode(l)));
        }
        if let Some(mg) = &self.message {
            q.push(format!("message={}", pct_encode(mg)));
        }
        if q.is_empty() {
            format!("bitcoin:{}", self.address)
        } else {
            format!("bitcoin:{}?{}", self.address, q.join("&"))
        }
    }

    /// Parse a BIP21 URI; unknown `req-` parameters are refused (as Armory did).
    pub fn parse(uri: &str) -> Result<Self> {
        let rest = uri
            .trim()
            .strip_prefix("bitcoin:")
            .or_else(|| uri.trim().strip_prefix("BITCOIN:"))
            .ok_or_else(|| anyhow!("not a bitcoin: URI"))?;
        let (addr, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut p = PaymentUri { address: addr.to_string(), ..Default::default() };
        for kv in query.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let v = pct_decode(v)?;
            match k.to_ascii_lowercase().as_str() {
                "amount" => p.amount_sat = Some(Amount::from_str_in(&v, Denomination::Bitcoin)?.to_sat()),
                "label" => p.label = Some(v),
                "message" => p.message = Some(v),
                other if other.starts_with("req-") => {
                    bail!("the payment request requires '{other}', which is not supported")
                }
                _ => {}
            }
        }
        Ok(p)
    }
}

#[derive(Subcommand)]
pub enum UriCmd {
    /// Create a payment request link.
    Create {
        address: String,
        /// Amount in BTC.
        #[arg(long)]
        amount: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        message: Option<String>,
        /// Also print a QR code.
        #[arg(long)]
        qr: bool,
    },
    /// Decode a payment request link.
    Parse { uri: String },
}

pub fn qr_text(data: &str) -> Result<String> {
    use qrcode::render::unicode;
    let code = qrcode::QrCode::new(data.as_bytes())?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

pub fn uri(ctx: &Context, json: bool, cmd: UriCmd) -> Result<()> {
    match cmd {
        UriCmd::Create { address, amount, label, message, qr } => {
            Address::from_str(&address)?
                .require_network(ctx.network.bitcoin())
                .map_err(|_| anyhow!("{address} is not an address for this network"))?;
            let amount_sat = amount
                .map(|a| Amount::from_str_in(&a, Denomination::Bitcoin).map(|x| x.to_sat()))
                .transpose()?;
            let u = PaymentUri { address, amount_sat, label, message }.to_uri();
            print(
                json,
                &u,
                |u| if qr { format!("{u}\n{}", qr_text(u).unwrap_or_default()) } else { u.clone() },
            );
        }
        UriCmd::Parse { uri } => {
            let p = PaymentUri::parse(&uri)?;
            print(json, &p, |p| {
                format!(
                    "Address: {}\nAmount:  {}\nLabel:   {}\nMessage: {}",
                    p.address,
                    p.amount_sat
                        .map(|a| format!("{} BTC", Amount::from_sat(a).to_string_in(Denomination::Bitcoin)))
                        .unwrap_or_default(),
                    p.label.clone().unwrap_or_default(),
                    p.message.clone().unwrap_or_default()
                )
            });
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ sweep

/// Keys to try for a typed private key: WIF says whether it is compressed; Armory hex and mini keys
/// may have been used either way.
fn sweep_keys(text: &str, network: bitcoin::Network) -> Result<Vec<SweepKey>> {
    if let Ok(k) = bitcoin::PrivateKey::from_wif(text.trim()) {
        if k.network != network.into() {
            bail!("the key is for another network");
        }
        return Ok(vec![SweepKey { secret: k.inner, compressed: k.compressed }]);
    }
    let raw =
        armory_wallet::keytext::parse_private_key(text, armory_wallet::modern::legacy_network(network))?;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&raw[..])?;
    Ok(vec![SweepKey { secret: sk, compressed: false }, SweepKey { secret: sk, compressed: true }])
}

pub fn sweep_key(
    ctx: &Context,
    node: &NodeArgs,
    json: bool,
    id: &str,
    fee: &FeeArgs,
    yes: bool,
) -> Result<()> {
    let (path, mut w) = m::open(ctx, id)?;
    let text = read_secret("Private key to sweep (WIF, hex or mini key): ")?;
    let keys = sweep_keys(&text, w.network)?;
    let core = Core::new(&node.config(), w.network);
    core.status()?;
    let rate = crate::ops::fee_rate(&core, fee)?;
    let mut txids = Vec::new();
    for key in keys {
        let found = core.scan_utxos(&key.descriptors())?;
        if found.is_empty() {
            continue;
        }
        let coins: Vec<SweepInput> = found
            .iter()
            .map(|u| {
                Ok(SweepInput {
                    outpoint: OutPoint::new(Txid::from_str(&u.txid)?, u.vout),
                    value: u.amount as u64,
                    script_pubkey: ScriptBuf::from_hex(&u.script_pubkey)?,
                })
            })
            .collect::<Result<_>>()?;
        let dest = w.next_receive(0)?;
        let tx = sweep::sweep(&key, &coins, &dest, rate)?;
        let total: u64 = coins.iter().map(|c| c.value).sum();
        eprintln!(
            "Sweeping {} coin(s), {} BTC, to {dest} (fee {} sat).",
            coins.len(),
            Amount::from_sat(total).to_string_in(Denomination::Bitcoin),
            total - tx.output[0].value.to_sat()
        );
        crate::cli_tx::confirm(yes, "Broadcast the sweep?")?;
        w.save(&path)?;
        txids.push(core.broadcast(&serialize_hex(&tx))?);
    }
    if txids.is_empty() {
        bail!("no coins found for this key (the UTXO set has none)");
    }
    print(json, &txids, |t| format!("Broadcast {}", t.join(", ")));
    Ok(())
}

// ------------------------------------------------------------------ tools

#[derive(Subcommand)]
pub enum ToolsCmd {
    /// Public key, addresses and WIF for a private key (read from the prompt).
    KeyInfo,
    /// Decode a raw transaction (hex).
    DecodeTx { hex: String },
}

pub fn tools(ctx: &Context, json: bool, cmd: ToolsCmd) -> Result<()> {
    let net = ctx.network.bitcoin();
    match cmd {
        ToolsCmd::KeyInfo => {
            let text = read_secret("Private key: ")?;
            let keys = sweep_keys(&text, net)?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let info: Vec<serde_json::Value> = keys
                .iter()
                .map(|k| {
                    let pk = k.secret.public_key(&secp);
                    serde_json::json!({
                        "compressed": k.compressed,
                        "public_key": if k.compressed { hex(&pk.serialize()) } else { hex(&pk.serialize_uncompressed()) },
                        "wif": bitcoin::PrivateKey { compressed: k.compressed, network: net.into(), inner: k.secret }.to_wif(),
                        "addresses": k.addresses(net).iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                    })
                })
                .collect();
            print(json, &info, |i| serde_json::to_string_pretty(i).unwrap_or_default());
        }
        ToolsCmd::DecodeTx { hex: h } => {
            let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(h.trim())?;
            let v = serde_json::json!({
                "txid": tx.compute_txid().to_string(),
                "vsize": tx.vsize(),
                "inputs": tx.input.iter().map(|i| i.previous_output.to_string()).collect::<Vec<_>>(),
                "outputs": tx.output.iter().map(|o| serde_json::json!({
                    "address": Address::from_script(&o.script_pubkey, net).map(|a| a.to_string()).unwrap_or_else(|_| o.script_pubkey.to_hex_string()),
                    "sat": o.value.to_sat(),
                })).collect::<Vec<_>>(),
            });
            print(json, &v, |v| serde_json::to_string_pretty(v).unwrap_or_default());
        }
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip21_roundtrip() {
        let u = PaymentUri {
            address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".into(),
            amount_sat: Some(150_000_000),
            label: Some("Rent & co".into()),
            message: Some("July".into()),
        };
        let s = u.to_uri();
        assert_eq!(
            s,
            "bitcoin:bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu?amount=1.5&label=Rent%20%26%20co&message=July"
        );
        assert_eq!(PaymentUri::parse(&s).unwrap(), u);
        assert!(PaymentUri::parse("bitcoin:x?req-somethingnew=1").is_err());
        assert_eq!(PaymentUri::parse("bitcoin:x?label=a+b").unwrap().label.as_deref(), Some("a b"));
    }

    #[test]
    fn qr_renders() {
        assert!(qr_text("bitcoin:x").unwrap().lines().count() > 10);
    }
}
