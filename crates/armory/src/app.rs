//! The service layer: every user-visible operation as a function returning plain data. The CLI
//! and the TUI are thin front-ends over this module.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail};
use armory_crypto::hash::hash160;
use armory_wallet::record::AddressRecord;
use armory_wallet::store::{self, WalletFile};
use armory_wallet::{Error as WErr, LegacyWallet, keytext};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::context::Context;

#[derive(Debug, Serialize)]
pub struct WalletSummary {
    pub id: String,
    pub label: String,
    pub description: String,
    pub kind: &'static str,
    pub encrypted: bool,
    pub created: u64,
    pub highest_used_index: i64,
    pub last_computed_index: i64,
    pub imported_keys: usize,
    pub kdf: Option<KdfSummary>,
    pub path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct KdfSummary {
    pub memory_bytes: u32,
    pub iterations: u32,
}

#[derive(Debug, Serialize)]
pub struct AddressInfo {
    pub address: String,
    pub chain_index: i64,
    pub used: bool,
    pub has_private_key: bool,
    pub label: Option<String>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn summary(f: &WalletFile) -> WalletSummary {
    let w = &f.wallet;
    WalletSummary {
        id: w.id(),
        label: w.label(),
        description: w.description(),
        kind: if w.is_watching_only() { "watching-only" } else { "full" },
        encrypted: w.is_encrypted(),
        created: w.create_date,
        highest_used_index: w.highest_used,
        last_computed_index: w.last_computed_index(),
        imported_keys: w.imported().len(),
        kdf: w
            .kdf
            .as_ref()
            .filter(|_| w.is_encrypted())
            .map(|k| KdfSummary { memory_bytes: k.memory_bytes, iterations: k.iterations }),
        path: f.paths.main.clone(),
    }
}

/// All wallets in the data directory, for the configured network.
pub fn list_wallets(ctx: &Context) -> Result<Vec<WalletFile>> {
    let mut out = Vec::new();
    for p in store::discover(&ctx.wallet_dir()?)? {
        match WalletFile::open(&p) {
            Ok(f) if f.wallet.network == ctx.network.legacy() => out.push(f),
            Ok(_) => {}
            Err(e) => eprintln!("warning: skipping {}: {e}", p.display()),
        }
    }
    Ok(out)
}

/// Find a wallet by ID (or unique ID prefix).
pub fn open_wallet(ctx: &Context, id: &str) -> Result<WalletFile> {
    let mut matches: Vec<WalletFile> =
        list_wallets(ctx)?.into_iter().filter(|f| f.wallet.id().starts_with(id)).collect();
    match matches.len() {
        0 => bail!("no wallet with ID {id} on {}", ctx.network.dir_name()),
        1 => Ok(matches.remove(0)),
        _ => bail!("wallet ID prefix {id} is ambiguous"),
    }
}

/// Unlock if encrypted: returns the AES key, or `None` for unencrypted wallets.
pub fn unlock(ctx: &Context, w: &LegacyWallet) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if !w.is_encrypted() {
        return Ok(None);
    }
    let pass = ctx.passphrase(&format!("Passphrase for wallet {}: ", w.id()))?;
    match w.unlock(pass.as_bytes()) {
        Ok(k) => Ok(Some(k)),
        Err(WErr::WrongPassphrase) => Err(anyhow!(WErr::WrongPassphrase)),
        Err(e) => Err(e.into()),
    }
}

pub struct CreateOptions<'a> {
    pub label: &'a str,
    pub description: &'a str,
    pub encrypt: bool,
    pub kdf_target: Duration,
    pub pool: Option<usize>,
    pub extra_entropy: Option<&'a [u8]>,
}

pub fn create_wallet(ctx: &Context, opts: &CreateOptions) -> Result<WalletFile> {
    let net = ctx.network.legacy();
    let pass = if opts.encrypt { Some(ctx.new_passphrase()?) } else { None };
    let w = LegacyWallet::create(
        net,
        opts.label,
        opts.description,
        pass.as_ref().map(|p| (p.as_bytes(), opts.kdf_target)),
        opts.pool.unwrap_or(net.default_pool_size()),
        opts.extra_entropy,
        now(),
    )?;
    let path = ctx.wallet_dir()?.join(w.default_file_name());
    Ok(WalletFile::create(&path, w)?)
}

/// Copy an existing `.wallet` file into the data directory (never moves the original).
pub fn import_wallet(ctx: &Context, src: &Path, replace: bool) -> Result<WalletFile> {
    let bytes = std::fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    let w = LegacyWallet::parse(&bytes)?;
    if w.network != ctx.network.legacy() {
        bail!("wallet {} is for {:?}, not {}", w.id(), w.network, ctx.network.dir_name());
    }
    if let Ok(existing) = open_wallet(ctx, &w.id()) {
        if existing.wallet.id() == w.id() && !replace {
            bail!("wallet {} already exists at {} (use --replace)", w.id(), existing.paths.main.display());
        }
    }
    let dest = ctx.wallet_dir()?.join(w.default_file_name());
    let paths = store::WalletPaths::new(&dest);
    for p in [&paths.main, &paths.backup, &paths.main_flag, &paths.backup_flag] {
        if p.exists() {
            std::fs::remove_file(p)?;
        }
    }
    Ok(WalletFile::create(&dest, w)?)
}

pub fn addresses(f: &WalletFile) -> Vec<AddressInfo> {
    let w = &f.wallet;
    let labels = w.address_comments();
    let mut out: Vec<AddressInfo> = w
        .chained()
        .values()
        .map(|r| info(w, r, &labels))
        .chain(w.imported().into_iter().map(|r| info(w, r, &labels)))
        .collect();
    out.sort_by_key(|a| if a.chain_index < 0 { i64::MAX } else { a.chain_index });
    out
}

fn info(
    w: &LegacyWallet,
    r: &AddressRecord,
    labels: &std::collections::BTreeMap<[u8; 20], String>,
) -> AddressInfo {
    AddressInfo {
        address: w.address(r),
        chain_index: r.chain_index,
        used: r.chain_index >= 0 && r.chain_index <= w.highest_used,
        has_private_key: r.flags.has_priv,
        label: labels.get(&r.addr160).filter(|l| !l.is_empty()).cloned(),
    }
}

/// Next unused receive address; refills the pool and saves the file (fsync) before returning.
pub fn new_address(ctx: &Context, f: &mut WalletFile, pool: Option<usize>) -> Result<AddressInfo> {
    let key =
        if f.wallet.is_encrypted() && !f.wallet.is_watching_only() { unlock(ctx, &f.wallet)? } else { None };
    let pool = pool.unwrap_or(f.wallet.network.default_pool_size());
    let idx = f.wallet.next_unused(pool, key.as_deref().map(|k| &k[..]))?;
    f.save()?;
    let r = f.wallet.record(idx).ok_or_else(|| anyhow!("index {idx} missing"))?;
    Ok(info(&f.wallet, r, &f.wallet.address_comments()))
}

/// Decode a P2PKH address into its hash160, checking the network.
pub fn decode_address(f: &WalletFile, address: &str) -> Result<[u8; 20]> {
    let raw = bitcoin_base58_check(address)?;
    if raw.len() != 21 || raw[0] != f.wallet.network.p2pkh_byte() {
        bail!("{address} is not a P2PKH address for this network");
    }
    Ok(raw[1..].try_into().unwrap())
}

fn bitcoin_base58_check(s: &str) -> Result<Vec<u8>> {
    let raw = armory_crypto::base58::decode(s)?;
    if raw.len() < 5 {
        bail!("invalid address");
    }
    let (body, chk) = raw.split_at(raw.len() - 4);
    if armory_crypto::hash::hash256(body)[..4] != *chk {
        bail!("address checksum mismatch");
    }
    Ok(body.to_vec())
}

/// Find which wallet holds an address.
pub fn find_address(ctx: &Context, address: &str) -> Result<(WalletFile, [u8; 20])> {
    for f in list_wallets(ctx)? {
        if let Ok(h) = decode_address(&f, address) {
            if f.wallet.record_by_hash160(&h).is_some() {
                return Ok((f, h));
            }
        }
    }
    bail!("address {address} is not in any wallet")
}

pub fn set_label(f: &mut WalletFile, h: [u8; 20], label: &str) -> Result<()> {
    f.wallet.set_address_comment(h, label);
    Ok(f.save()?)
}

#[derive(Debug, Serialize)]
pub struct KeyExport {
    pub address: String,
    pub wif: String,
    pub private_key_hex: String,
    pub public_key_hex: String,
}

pub fn export_key(ctx: &Context, f: &WalletFile, h: [u8; 20]) -> Result<KeyExport> {
    let key = unlock(ctx, &f.wallet)?;
    let k = f.wallet.private_key_for(&h, key.as_deref().map(|k| &k[..]))?;
    let pubk = armory_crypto::chain::public_key(&k)?;
    debug_assert_eq!(hash160(&pubk), h);
    Ok(KeyExport {
        address: f.wallet.network.p2pkh_address(&h),
        wif: f.wallet.network.wif(&k),
        private_key_hex: armory_crypto_hex(&k[..]),
        public_key_hex: armory_crypto_hex(&pubk),
    })
}

fn armory_crypto_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn import_key(ctx: &Context, f: &mut WalletFile, text: &str) -> Result<String> {
    let k = keytext::parse_private_key(text, f.wallet.network)?;
    let key = unlock(ctx, &f.wallet)?;
    let h = f.wallet.import_private_key(&k, key.as_deref().map(|k| &k[..]))?;
    f.save()?;
    Ok(f.wallet.network.p2pkh_address(&h))
}

pub fn remove_imported(f: &mut WalletFile, h: [u8; 20]) -> Result<()> {
    f.wallet.remove_imported(&h)?;
    Ok(f.save()?)
}

pub enum PassphraseChange {
    Set,
    Change,
    Remove,
}

pub fn change_passphrase(
    ctx: &Context,
    f: &mut WalletFile,
    what: PassphraseChange,
    target: Duration,
) -> Result<()> {
    use armory_crypto::kdf::KdfParams;
    let old = match what {
        PassphraseChange::Set => {
            if f.wallet.is_encrypted() {
                bail!("wallet is already encrypted; use `change`");
            }
            None
        }
        _ => {
            if !f.wallet.is_encrypted() {
                bail!("wallet is not encrypted; use `set`");
            }
            unlock(ctx, &f.wallet)?
        }
    };
    let new_pass = match what {
        PassphraseChange::Remove => None,
        _ => Some(ctx.new_passphrase()?),
    };
    let params = new_pass.as_ref().map(|_| KdfParams::calibrate(target, 32 * 1024 * 1024));
    let new = params.zip(new_pass.as_ref()).map(|(p, s)| (p, s.as_bytes()));
    f.wallet.change_encryption(old.as_deref().map(|k| &k[..]), new)?;
    Ok(f.save()?)
}

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub id: String,
    pub chained_addresses_verified: usize,
    pub private_keys_checked: bool,
    pub repaired_on_read: bool,
    pub recovery: String,
}

pub fn check_wallet(ctx: &Context, f: &WalletFile, with_keys: bool) -> Result<CheckReport> {
    let key = if with_keys && !f.wallet.is_watching_only() { unlock(ctx, &f.wallet)? } else { None };
    let n = f.wallet.verify_chain(key.as_deref().map(|k| &k[..]))?;
    Ok(CheckReport {
        id: f.wallet.id(),
        chained_addresses_verified: n,
        private_keys_checked: with_keys && !f.wallet.is_watching_only(),
        repaired_on_read: f.wallet.repaired,
        recovery: format!("{:?}", f.recovery),
    })
}

pub fn export_watching_only(f: &WalletFile, dest: &Path) -> Result<PathBuf> {
    let wo = f.wallet.watching_only_copy();
    let dest = if dest.is_dir() {
        dest.join(format!("armory_{}_WatchOnly.wallet", wo.id()))
    } else {
        dest.to_path_buf()
    };
    if dest.exists() {
        bail!("{} already exists", dest.display());
    }
    store::atomic_write(&dest, &wo.serialize())?;
    Ok(dest)
}
