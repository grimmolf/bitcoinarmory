//! The modern Armory wallet (format v2): BIP39 + BIP32 accounts (BIP84 / BIP86), migrated
//! legacy-1.35 accounts, Argon2id + XChaCha20-Poly1305 for secrets. See
//! `docs/rust-rebuild/02-modern-wallet-format.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use argon2::{Algorithm, Argon2, Params, Version};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::key::{CompressedPublicKey, Secp256k1};
use bitcoin::{Address, Network};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::descriptor::with_checksum;
use crate::{LegacyNetwork, LegacyWallet, store};

pub const FORMAT: &str = "armory-wallet";
pub const VERSION: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum ModernError {
    #[error("not an Armory v2 wallet file")]
    NotAWallet,
    #[error("unsupported wallet format version {0}")]
    UnsupportedVersion(u32),
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("wallet is watching-only")]
    WatchingOnly,
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),
    #[error(
        "public account data does not match the secrets ({0}); the wallet file may have been tampered with"
    )]
    Tampered(String),
    #[error("no account {0}")]
    NoSuchAccount(usize),
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Legacy(#[from] crate::Error),
    #[error(transparent)]
    Crypto(#[from] armory_crypto::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ModernError>;

fn invalid(e: impl std::fmt::Display) -> ModernError {
    ModernError::Invalid(e.to_string())
}

/// Account types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountKind {
    /// BIP84 native SegWit (P2WPKH).
    Bip84,
    /// BIP86 Taproot (P2TR, key path only).
    Bip86,
    /// Keys migrated from an Armory v1.35 wallet (P2PKH, uncompressed keys).
    #[serde(rename = "legacy-1.35")]
    Legacy135,
}

impl AccountKind {
    pub fn purpose(self) -> Option<u32> {
        match self {
            AccountKind::Bip84 => Some(84),
            AccountKind::Bip86 => Some(86),
            AccountKind::Legacy135 => None,
        }
    }
}

/// Public data of one account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub kind: AccountKind,
    pub name: String,
    /// Account-level extended public key (BIP84/BIP86).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xpub: Option<String>,
    /// e.g. `m/84h/0h/0h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Legacy accounts: the v1.35 wallet ID, root public key (65 bytes) and chain code, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<LegacyPublic>,
    /// Next unused receive index (`/0/*`; legacy: chain index).
    pub next_receive: u32,
    /// Next unused change index (`/1/*`; unused for legacy accounts).
    pub next_change: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyPublic {
    pub wallet_id: String,
    pub root_pubkey: String,
    pub chaincode: String,
    /// Watch-only addresses of keys imported into the legacy wallet (hash160, hex).
    #[serde(default)]
    pub imported_hash160: Vec<String>,
}

/// Secret material. Zeroized on drop.
#[derive(Default, Serialize, Deserialize)]
pub struct Secrets {
    /// BIP39 entropy (16 or 32 bytes), hex.
    pub entropy: String,
    #[serde(default)]
    pub bip39_passphrase: String,
    /// Legacy accounts: wallet ID -> (root private key hex, chain code hex).
    #[serde(default)]
    pub legacy_roots: BTreeMap<String, (String, String)>,
    /// Imported private keys of migrated legacy wallets: hash160 hex -> 32-byte key hex.
    #[serde(default)]
    pub imported_keys: BTreeMap<String, String>,
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.entropy.zeroize();
        self.bip39_passphrase.zeroize();
        for (a, b) in self.legacy_roots.values_mut() {
            a.zeroize();
            b.zeroize();
        }
        for k in self.imported_keys.values_mut() {
            k.zeroize();
        }
    }
}

/// Argon2id parameters stored in the file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    #[serde(with = "hex_array")]
    pub salt: [u8; 16],
}

impl KdfParams {
    /// Default: 256 MiB, 3 passes, 1 lane, random salt.
    pub fn recommended() -> Self {
        Self::with_cost(256 * 1024, 3)
    }

    pub fn with_cost(memory_kib: u32, iterations: u32) -> Self {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Self { memory_kib, iterations, parallelism: 1, salt }
    }

    fn derive(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params =
            Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32)).map_err(invalid)?;
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase, &self.salt, &mut out[..])
            .map_err(invalid)?;
        Ok(out)
    }
}

mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

/// How the secrets are stored.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SecretBox {
    WatchingOnly,
    Plaintext { secrets: serde_json::Value },
    Encrypted { kdf: KdfParams, nonce: String, ciphertext: String },
}

/// The wallet file contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModernWallet {
    pub format: String,
    pub version: u32,
    pub network: Network,
    /// BIP32 master fingerprint, hex.
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    pub created: u64,
    /// Earliest time (unix seconds) the wallet can have received funds; 0 = unknown (restored or
    /// migrated wallets), which makes a backend rescan from the genesis block.
    #[serde(default)]
    pub birthday: u64,
    pub accounts: Vec<Account>,
    /// Address -> label.
    #[serde(default)]
    pub address_labels: BTreeMap<String, String>,
    /// Txid (display order) -> comment.
    #[serde(default)]
    pub tx_comments: BTreeMap<String, String>,
    pub secrets: SecretBox,
}

impl std::fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SecretBox::WatchingOnly => "WatchingOnly",
            SecretBox::Plaintext { .. } => "Plaintext(<redacted>)",
            SecretBox::Encrypted { .. } => "Encrypted(<sealed>)",
        })
    }
}

fn coin_type(network: Network) -> u32 {
    if network == Network::Bitcoin { 0 } else { 1 }
}

pub fn legacy_network(network: Network) -> LegacyNetwork {
    if network == Network::Bitcoin { LegacyNetwork::Mainnet } else { LegacyNetwork::Testnet }
}

/// A freshly generated or restored mnemonic, to show to the user once.
pub struct NewWallet {
    pub wallet: ModernWallet,
    pub mnemonic: Zeroizing<String>,
}

/// (v1.35 wallet ID, root private key, chain code).
pub type LegacyRootSecret = (String, Zeroizing<[u8; 32]>, [u8; 32]);

/// Unlocked secrets.
pub struct Unlocked {
    pub secrets: Secrets,
    master: Xpriv,
}

impl Unlocked {
    pub fn entropy(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(hex::decode(&self.secrets.entropy).map_err(invalid)?))
    }

    /// Migrated legacy roots: (v1.35 wallet ID, root key, chain code).
    pub fn legacy_roots(&self) -> Result<Vec<LegacyRootSecret>> {
        self.secrets
            .legacy_roots
            .iter()
            .map(|(id, (r, c))| {
                let root =
                    Zeroizing::new(hex::decode(r).map_err(invalid)?.try_into().map_err(|_| invalid("key"))?);
                let cc = hex::decode(c).map_err(invalid)?.try_into().map_err(|_| invalid("chaincode"))?;
                Ok((id.clone(), root, cc))
            })
            .collect()
    }

    pub fn mnemonic(&self) -> Result<Zeroizing<String>> {
        let entropy = Zeroizing::new(hex::decode(&self.secrets.entropy).map_err(invalid)?);
        let m = bip39::Mnemonic::from_entropy(&entropy).map_err(|e| ModernError::Mnemonic(e.to_string()))?;
        Ok(Zeroizing::new(m.words().collect::<Vec<_>>().join(" ")))
    }

    pub fn master(&self) -> &Xpriv {
        &self.master
    }
}

fn master_from(entropy: &[u8], bip39_passphrase: &str, network: Network) -> Result<Xpriv> {
    let m = bip39::Mnemonic::from_entropy(entropy).map_err(|e| ModernError::Mnemonic(e.to_string()))?;
    let seed = Zeroizing::new(m.to_seed(bip39_passphrase));
    Xpriv::new_master(network, &seed[..]).map_err(invalid)
}

fn aad(format: &str, version: u32, network: Network, id: &str) -> Vec<u8> {
    format!("{format}|{version}|{network}|{id}").into_bytes()
}

impl ModernWallet {
    // ------------------------------------------------------------- creation

    /// New wallet with a fresh mnemonic (`words` = 12 or 24) and one BIP84 account.
    pub fn generate(
        network: Network,
        label: &str,
        words: usize,
        bip39_passphrase: &str,
        encryption: Option<(&[u8], KdfParams)>,
        extra_entropy: Option<&[u8]>,
        now: u64,
    ) -> Result<NewWallet> {
        let len = match words {
            12 => 16,
            24 => 32,
            _ => return Err(invalid("mnemonic must have 12 or 24 words")),
        };
        let mut entropy = Zeroizing::new(vec![0u8; len]);
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        if let Some(extra) = extra_entropy {
            let mut mix = entropy.to_vec();
            mix.extend_from_slice(extra);
            let h = armory_crypto::hash::sha256(&mix);
            mix.zeroize();
            entropy.copy_from_slice(&h[..len]);
        }
        let mut nw = Self::from_entropy(network, label, &entropy, bip39_passphrase, encryption, now)?;
        // A brand-new seed cannot have history; allow two hours for clock skew.
        nw.wallet.birthday = now.saturating_sub(7200);
        Ok(nw)
    }

    /// Restore from a mnemonic.
    pub fn restore(
        network: Network,
        label: &str,
        mnemonic: &str,
        bip39_passphrase: &str,
        encryption: Option<(&[u8], KdfParams)>,
        now: u64,
    ) -> Result<NewWallet> {
        let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
            .map_err(|e| ModernError::Mnemonic(e.to_string()))?;
        let entropy = Zeroizing::new(m.to_entropy());
        Self::from_entropy(network, label, &entropy, bip39_passphrase, encryption, now)
    }

    /// Restore from raw BIP39 entropy (a paper or fragment backup).
    pub fn restore_entropy(
        network: Network,
        label: &str,
        entropy: &[u8],
        bip39_passphrase: &str,
        encryption: Option<(&[u8], KdfParams)>,
        now: u64,
    ) -> Result<NewWallet> {
        Self::from_entropy(network, label, entropy, bip39_passphrase, encryption, now)
    }

    fn from_entropy(
        network: Network,
        label: &str,
        entropy: &[u8],
        bip39_passphrase: &str,
        encryption: Option<(&[u8], KdfParams)>,
        now: u64,
    ) -> Result<NewWallet> {
        let secp = Secp256k1::new();
        let master = master_from(entropy, bip39_passphrase, network)?;
        let id = master.fingerprint(&secp).to_string();
        let mut w = ModernWallet {
            format: FORMAT.into(),
            version: VERSION,
            network,
            id,
            label: label.into(),
            description: String::new(),
            created: now,
            birthday: 0,
            accounts: Vec::new(),
            address_labels: BTreeMap::new(),
            tx_comments: BTreeMap::new(),
            secrets: SecretBox::WatchingOnly,
        };
        w.add_bip32_account(&master, AccountKind::Bip84, 0)?;
        let mut secrets = Secrets::default();
        secrets.entropy = hex::encode(entropy);
        secrets.bip39_passphrase = bip39_passphrase.into();
        w.seal(&secrets, encryption)?;
        let unlocked = Unlocked { secrets, master };
        let mnemonic = unlocked.mnemonic()?;
        Ok(NewWallet { wallet: w, mnemonic })
    }

    fn add_bip32_account(&mut self, master: &Xpriv, kind: AccountKind, index: u32) -> Result<usize> {
        let secp = Secp256k1::new();
        let purpose = kind.purpose().ok_or_else(|| invalid("not a BIP32 account type"))?;
        let path_str = format!("m/{purpose}h/{}h/{index}h", coin_type(self.network));
        let path = DerivationPath::from_str(&path_str.replace('h', "'")).map_err(invalid)?;
        let acct = master.derive_priv(&secp, &path).map_err(invalid)?;
        let xpub = Xpub::from_priv(&secp, &acct);
        if self.accounts.iter().any(|a| a.path.as_deref() == Some(path_str.as_str())) {
            return Err(invalid(format!("account {path_str} already exists")));
        }
        let name = match kind {
            AccountKind::Bip84 => format!("SegWit {index}"),
            AccountKind::Bip86 => format!("Taproot {index}"),
            AccountKind::Legacy135 => unreachable!(),
        };
        self.accounts.push(Account {
            kind,
            name,
            xpub: Some(xpub.to_string()),
            path: Some(path_str),
            legacy: None,
            next_receive: 0,
            next_change: 0,
        });
        Ok(self.accounts.len() - 1)
    }

    /// Add a BIP84 or BIP86 account (needs the secrets).
    pub fn add_account(&mut self, unlocked: &Unlocked, kind: AccountKind, index: u32) -> Result<usize> {
        self.add_bip32_account(&unlocked.master, kind, index)
    }

    // ------------------------------------------------------------- secrets

    fn seal(&mut self, secrets: &Secrets, encryption: Option<(&[u8], KdfParams)>) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(secrets)?);
        self.secrets = match encryption {
            None => SecretBox::Plaintext { secrets: serde_json::from_slice(&plain)? },
            Some((pass, kdf)) => {
                let key = kdf.derive(pass)?;
                let mut nonce = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let cipher = XChaCha20Poly1305::new(key[..].into());
                let aad = aad(&self.format, self.version, self.network, &self.id);
                let ct = cipher
                    .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad })
                    .map_err(|_| invalid("encryption failed"))?;
                SecretBox::Encrypted { kdf, nonce: hex::encode(nonce), ciphertext: hex::encode(ct) }
            }
        };
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self.secrets, SecretBox::Encrypted { .. })
    }

    pub fn is_watching_only(&self) -> bool {
        matches!(self.secrets, SecretBox::WatchingOnly)
    }

    /// Decrypt the secrets (`passphrase` is ignored for unencrypted wallets).
    pub fn unlock(&self, passphrase: Option<&[u8]>) -> Result<Unlocked> {
        let secrets: Secrets = match &self.secrets {
            SecretBox::WatchingOnly => return Err(ModernError::WatchingOnly),
            SecretBox::Plaintext { secrets } => serde_json::from_value(secrets.clone())?,
            SecretBox::Encrypted { kdf, nonce, ciphertext } => {
                let pass = passphrase.ok_or(ModernError::WrongPassphrase)?;
                let key = kdf.derive(pass)?;
                let cipher = XChaCha20Poly1305::new(key[..].into());
                let nonce = hex::decode(nonce).map_err(invalid)?;
                let ct = hex::decode(ciphertext).map_err(invalid)?;
                let aad = aad(&self.format, self.version, self.network, &self.id);
                let plain = Zeroizing::new(
                    cipher
                        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad: &aad })
                        .map_err(|_| ModernError::WrongPassphrase)?,
                );
                serde_json::from_slice(&plain)?
            }
        };
        let entropy = Zeroizing::new(hex::decode(&secrets.entropy).map_err(invalid)?);
        let master = master_from(&entropy, &secrets.bip39_passphrase, self.network)?;
        if master.fingerprint(&Secp256k1::new()).to_string() != self.id {
            return Err(ModernError::Tampered("master fingerprint".into()));
        }
        let unlocked = Unlocked { secrets, master };
        self.verify_public(&unlocked)?;
        Ok(unlocked)
    }

    /// Check every account's public data against the secrets: BIP32 xpubs are re-derived from
    /// their paths, legacy root public keys and chain codes from the migrated roots, imported
    /// addresses from their keys. Run on every unlock.
    pub fn verify_public(&self, unlocked: &Unlocked) -> Result<()> {
        let secp = Secp256k1::new();
        for (i, a) in self.accounts.iter().enumerate() {
            match a.kind {
                AccountKind::Bip84 | AccountKind::Bip86 => {
                    let path_str =
                        a.path.clone().ok_or_else(|| ModernError::Tampered(format!("account {i} path")))?;
                    let want_prefix =
                        format!("m/{}h/{}h/", a.kind.purpose().unwrap(), coin_type(self.network));
                    if !path_str.starts_with(&want_prefix) {
                        return Err(ModernError::Tampered(format!("account {i} path")));
                    }
                    let path = DerivationPath::from_str(&path_str.replace('h', "'")).map_err(invalid)?;
                    let x =
                        Xpub::from_priv(&secp, &unlocked.master.derive_priv(&secp, &path).map_err(invalid)?);
                    if a.xpub.as_deref() != Some(x.to_string().as_str()) {
                        return Err(ModernError::Tampered(format!("account {i} xpub")));
                    }
                }
                AccountKind::Legacy135 => {
                    let l = a.legacy.as_ref().ok_or_else(|| ModernError::Tampered(format!("account {i}")))?;
                    let (root_hex, cc_hex) = unlocked
                        .secrets
                        .legacy_roots
                        .get(&l.wallet_id)
                        .ok_or_else(|| ModernError::Tampered(format!("account {i} legacy id")))?;
                    let root: Zeroizing<[u8; 32]> = Zeroizing::new(
                        hex::decode(root_hex).map_err(invalid)?.try_into().map_err(|_| invalid("key"))?,
                    );
                    let pubk = armory_crypto::chain::public_key(&root)?;
                    if hex::encode(pubk) != l.root_pubkey || *cc_hex != l.chaincode {
                        return Err(ModernError::Tampered(format!("account {i} legacy root")));
                    }
                    for h in &l.imported_hash160 {
                        let k = unlocked
                            .secrets
                            .imported_keys
                            .get(h)
                            .ok_or_else(|| ModernError::Tampered(format!("account {i} imported key")))?;
                        let k: [u8; 32] =
                            hex::decode(k).map_err(invalid)?.try_into().map_err(|_| invalid("key"))?;
                        let pk = armory_crypto::chain::public_key(&k)?;
                        if hex::encode(armory_crypto::hash::hash160(&pk)) != *h {
                            return Err(ModernError::Tampered(format!("account {i} imported key")));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Re-seal the secrets: set, change or remove the passphrase.
    pub fn reseal(&mut self, unlocked: &Unlocked, encryption: Option<(&[u8], KdfParams)>) -> Result<()> {
        self.seal(&unlocked.secrets, encryption)
    }

    /// Store updated secrets with the current protection (re-encrypting with `passphrase`).
    fn update_secrets(&mut self, secrets: &Secrets, passphrase: Option<&[u8]>) -> Result<()> {
        let enc = match &self.secrets {
            SecretBox::Encrypted { .. } => {
                let pass = passphrase.ok_or(ModernError::WrongPassphrase)?;
                Some((pass, KdfParams::with_cost(self.kdf_cost().0, self.kdf_cost().1)))
            }
            _ => None,
        };
        self.seal(secrets, enc)
    }

    fn kdf_cost(&self) -> (u32, u32) {
        match &self.secrets {
            SecretBox::Encrypted { kdf, .. } => (kdf.memory_kib, kdf.iterations),
            _ => (256 * 1024, 3),
        }
    }

    /// A copy without any secrets.
    pub fn watching_only_copy(&self) -> Self {
        let mut w = self.clone();
        w.secrets = SecretBox::WatchingOnly;
        w.label = format!("{} (watching-only)", self.label);
        w
    }

    // ------------------------------------------------------------- addresses

    pub fn account(&self, i: usize) -> Result<&Account> {
        self.accounts.get(i).ok_or(ModernError::NoSuchAccount(i))
    }

    fn xpub(&self, a: &Account) -> Result<Xpub> {
        Xpub::from_str(a.xpub.as_deref().ok_or_else(|| invalid("account has no xpub"))?).map_err(invalid)
    }

    /// Address of `account` on branch `change` (0 receive, 1 change) at `index`.
    pub fn address(&self, account: usize, change: u32, index: u32) -> Result<Address> {
        let a = self.account(account)?;
        let secp = Secp256k1::verification_only();
        match a.kind {
            AccountKind::Bip84 | AccountKind::Bip86 => {
                let xpub = self.xpub(a)?;
                let child = xpub
                    .derive_pub(
                        &secp,
                        &[
                            ChildNumber::from_normal_idx(change).map_err(invalid)?,
                            ChildNumber::from_normal_idx(index).map_err(invalid)?,
                        ],
                    )
                    .map_err(invalid)?;
                Ok(if a.kind == AccountKind::Bip84 {
                    Address::p2wpkh(&CompressedPublicKey(child.public_key), self.network)
                } else {
                    Address::p2tr(&secp, child.to_x_only_pub(), None, self.network)
                })
            }
            AccountKind::Legacy135 => {
                let pubk = self.legacy_pubkey(a, index)?;
                let net = legacy_network(self.network);
                Ok(Address::from_str(&net.p2pkh_address(&armory_crypto::hash::hash160(&pubk)))
                    .map_err(invalid)?
                    .require_network(self.network)
                    .map_err(invalid)?)
            }
        }
    }

    fn legacy_pubkey(&self, a: &Account, index: u32) -> Result<[u8; 65]> {
        let l = a.legacy.as_ref().ok_or_else(|| invalid("legacy account without data"))?;
        let mut pubk: [u8; 65] =
            hex::decode(&l.root_pubkey).map_err(invalid)?.try_into().map_err(|_| invalid("pubkey"))?;
        let cc: [u8; 32] =
            hex::decode(&l.chaincode).map_err(invalid)?.try_into().map_err(|_| invalid("chaincode"))?;
        for _ in 0..=index {
            pubk = armory_crypto::chain::chained_public_key(&pubk, &cc)?;
        }
        Ok(pubk)
    }

    /// Hand out the next receive address of an account. Never needs the passphrase.
    pub fn next_receive(&mut self, account: usize) -> Result<Address> {
        let idx = self.account(account)?.next_receive;
        let addr = self.address(account, 0, idx)?;
        self.accounts[account].next_receive += 1;
        Ok(addr)
    }

    /// The next change address (BIP32 accounts only).
    pub fn next_change(&mut self, account: usize) -> Result<Address> {
        if self.account(account)?.kind == AccountKind::Legacy135 {
            return Err(invalid("legacy accounts have no change branch"));
        }
        let idx = self.accounts[account].next_change;
        let addr = self.address(account, 1, idx)?;
        self.accounts[account].next_change += 1;
        Ok(addr)
    }

    /// Public descriptors (with checksums) for watch-only import, e.g. into Bitcoin Core.
    /// Legacy accounts produce one `pkh(<pubkey>)` per address up to `legacy_count`.
    pub fn public_descriptors(&self, account: usize, legacy_count: u32) -> Result<Vec<String>> {
        let a = self.account(account)?;
        match a.kind {
            AccountKind::Bip84 | AccountKind::Bip86 => {
                let origin =
                    format!("[{}{}]", self.id, a.path.as_deref().unwrap_or("m").trim_start_matches('m'));
                let f = if a.kind == AccountKind::Bip84 { "wpkh" } else { "tr" };
                let x = a.xpub.as_deref().unwrap_or_default();
                Ok((0..2).map(|b| with_checksum(&format!("{f}({origin}{x}/{b}/*)"))).collect())
            }
            AccountKind::Legacy135 => {
                let l = a.legacy.as_ref().ok_or_else(|| invalid("legacy account without data"))?;
                let mut out = Vec::new();
                for i in 0..legacy_count.max(a.next_receive) {
                    out.push(with_checksum(&format!("pkh({})", hex::encode(self.legacy_pubkey(a, i)?))));
                }
                for h in &l.imported_hash160 {
                    let addr = legacy_network(self.network).p2pkh_address(
                        &hex::decode(h).map_err(invalid)?.try_into().map_err(|_| invalid("hash160"))?,
                    );
                    out.push(with_checksum(&format!("addr({addr})")));
                }
                Ok(out)
            }
        }
    }

    /// Private descriptors (xprv), for export to another wallet.
    pub fn private_descriptors(&self, unlocked: &Unlocked, account: usize) -> Result<Vec<String>> {
        let a = self.account(account)?;
        if a.kind == AccountKind::Legacy135 {
            return Err(invalid("legacy-1.35 keys are not BIP32; use `armory legacy address keys`"));
        }
        let secp = Secp256k1::new();
        let path_str = a.path.clone().unwrap_or_default();
        let path = DerivationPath::from_str(&path_str.replace('h', "'")).map_err(invalid)?;
        let acct = unlocked.master.derive_priv(&secp, &path).map_err(invalid)?;
        let origin = format!("[{}{}]", self.id, path_str.trim_start_matches('m'));
        let f = if a.kind == AccountKind::Bip84 { "wpkh" } else { "tr" };
        Ok((0..2).map(|b| with_checksum(&format!("{f}({origin}{acct}/{b}/*)"))).collect())
    }

    pub fn master_fingerprint(&self) -> Result<Fingerprint> {
        Fingerprint::from_str(&self.id).map_err(invalid)
    }

    /// Where an address of this wallet lives: `(account, branch, index)`, searching handed-out
    /// addresses plus `gap` more on each branch. Imported legacy keys return index `u32::MAX`.
    pub fn find_address(&self, address: &Address, gap: u32) -> Option<(usize, u32, u32)> {
        let spk = address.script_pubkey();
        for (i, a) in self.accounts.iter().enumerate() {
            let branches: &[(u32, u32)] = if a.kind == AccountKind::Legacy135 {
                &[(0, a.next_receive)]
            } else {
                &[(0, a.next_receive), (1, a.next_change)]
            };
            for (b, n) in branches {
                for idx in 0..n + gap {
                    if self.address(i, *b, idx).is_ok_and(|x| x.script_pubkey() == spk) {
                        return Some((i, *b, idx));
                    }
                }
            }
            if let Some(l) = &a.legacy {
                for h in &l.imported_hash160 {
                    let addr =
                        legacy_network(self.network).p2pkh_address(&hex::decode(h).ok()?.try_into().ok()?);
                    if addr == address.to_string() {
                        return Some((i, 0, u32::MAX));
                    }
                }
            }
        }
        None
    }

    /// Private key of one of this wallet's addresses. The flag is true for compressed keys
    /// (BIP32 accounts) and false for legacy-1.35 keys (uncompressed).
    pub fn key_for_address(
        &self,
        unlocked: &Unlocked,
        address: &Address,
        gap: u32,
    ) -> Result<(bitcoin::secp256k1::SecretKey, bool)> {
        let (acct, branch, idx) =
            self.find_address(address, gap).ok_or_else(|| invalid("address is not in this wallet"))?;
        let a = &self.accounts[acct];
        let sk = match a.kind {
            AccountKind::Legacy135 if idx == u32::MAX => {
                let h = hex::encode(&address.script_pubkey().as_bytes()[3..23]);
                let k =
                    unlocked.secrets.imported_keys.get(&h).ok_or_else(|| invalid("missing imported key"))?;
                bitcoin::secp256k1::SecretKey::from_slice(&hex::decode(k).map_err(invalid)?)
                    .map_err(invalid)?
            }
            AccountKind::Legacy135 => {
                let k = self.legacy_private_key(unlocked, acct, idx)?;
                bitcoin::secp256k1::SecretKey::from_slice(&k[..]).map_err(invalid)?
            }
            _ => {
                let secp = Secp256k1::new();
                let path = DerivationPath::from_str(
                    &format!("{}/{branch}/{idx}", a.path.clone().unwrap_or_default()).replace('h', "'"),
                )
                .map_err(invalid)?;
                unlocked.master.derive_priv(&secp, &path).map_err(invalid)?.private_key
            }
        };
        Ok((sk, a.kind != AccountKind::Legacy135))
    }

    // ------------------------------------------------------------- migration

    /// Add a legacy v1.35 wallet as a `legacy-1.35` account. `legacy_key` is the v1.35 AES key
    /// when that wallet is encrypted; `passphrase` re-seals this wallet's secrets.
    pub fn migrate_legacy(
        &mut self,
        unlocked: &mut Unlocked,
        legacy: &LegacyWallet,
        legacy_key: Option<&[u8]>,
        passphrase: Option<&[u8]>,
    ) -> Result<usize> {
        if legacy_network(self.network) != legacy.network {
            return Err(invalid("the legacy wallet is for a different network"));
        }
        if legacy.is_watching_only() {
            return Err(invalid("watching-only legacy wallets cannot be migrated (no keys)"));
        }
        let id = legacy.id();
        if unlocked.secrets.legacy_roots.contains_key(&id) {
            return Err(invalid(format!("legacy wallet {id} is already migrated")));
        }
        legacy.verify_chain(legacy_key)?;
        let (root, cc) = legacy.root_secret(legacy_key)?;
        let mut imported_hash = Vec::new();
        for r in legacy.imported() {
            let k = legacy.private_key_for(&r.addr160, legacy_key)?;
            unlocked.secrets.imported_keys.insert(hex::encode(r.addr160), hex::encode(*k));
            imported_hash.push(hex::encode(r.addr160));
        }
        unlocked.secrets.legacy_roots.insert(id.clone(), (hex::encode(*root), hex::encode(cc)));
        let root_pub = legacy.root.pubkey65().ok_or_else(|| invalid("legacy root has no public key"))?;
        self.accounts.push(Account {
            kind: AccountKind::Legacy135,
            name: format!("Armory 1.35 {id} ({})", legacy.label()),
            xpub: None,
            path: None,
            legacy: Some(LegacyPublic {
                wallet_id: id,
                root_pubkey: hex::encode(root_pub),
                chaincode: hex::encode(cc),
                imported_hash160: imported_hash,
            }),
            next_receive: (legacy.highest_used + 1).max(0) as u32,
            next_change: 0,
        });
        let net = legacy.network;
        for (h, c) in legacy.address_comments() {
            if !c.is_empty() {
                self.address_labels.insert(net.p2pkh_address(&h), c);
            }
        }
        for (h, c) in legacy.tx_comments() {
            let mut display = h;
            display.reverse();
            if !c.is_empty() {
                self.tx_comments.insert(hex::encode(display), c);
            }
        }
        self.update_secrets(&unlocked.secrets, passphrase)?;
        Ok(self.accounts.len() - 1)
    }

    /// Private key of a legacy-account address (chain index), via the migrated root.
    pub fn legacy_private_key(
        &self,
        unlocked: &Unlocked,
        account: usize,
        index: u32,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let a = self.account(account)?;
        let l = a.legacy.as_ref().ok_or_else(|| invalid("not a legacy account"))?;
        let (root_hex, cc_hex) = unlocked
            .secrets
            .legacy_roots
            .get(&l.wallet_id)
            .ok_or_else(|| invalid("missing legacy secret"))?;
        let mut k = Zeroizing::new(
            <[u8; 32]>::try_from(hex::decode(root_hex).map_err(invalid)?).map_err(|_| invalid("key"))?,
        );
        let cc: [u8; 32] =
            hex::decode(cc_hex).map_err(invalid)?.try_into().map_err(|_| invalid("chaincode"))?;
        for _ in 0..=index {
            k = armory_crypto::chain::chained_private_key(&k, &cc)?;
        }
        Ok(k)
    }

    // ------------------------------------------------------------- files

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ModernError::NotAWallet)?;
        if v.get("format").and_then(|f| f.as_str()) != Some(FORMAT) {
            return Err(ModernError::NotAWallet);
        }
        let version = v.get("version").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
        if version != VERSION {
            return Err(ModernError::UnsupportedVersion(version));
        }
        Ok(serde_json::from_value(v)?)
    }

    pub fn file_name(&self) -> String {
        format!("{}.armory", self.id)
    }

    /// Write `<path>` and `<path>.bak` atomically (mode 0600).
    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = self.to_json()?;
        store::atomic_write(path, &bytes)?;
        store::atomic_write(&backup_path(path), &bytes)?;
        Ok(())
    }

    /// Load, falling back to the `.bak` twin if the main file is damaged.
    pub fn load(path: &Path) -> Result<Self> {
        store::check_permissions(path)?;
        match std::fs::read(path).map_err(ModernError::from).and_then(|b| Self::from_json(&b)) {
            Ok(w) => Ok(w),
            Err(e) => {
                let bak = backup_path(path);
                if bak.exists() {
                    let w = Self::from_json(&std::fs::read(&bak)?)?;
                    w.save(path)?;
                    Ok(w)
                } else {
                    Err(e)
                }
            }
        }
    }
}

pub fn backup_path(path: &Path) -> PathBuf {
    let mut n = path.file_name().unwrap_or_default().to_os_string();
    n.push(".bak");
    path.with_file_name(n)
}

/// `*.armory` files in a directory.
pub fn discover(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if dir.exists() {
        for e in std::fs::read_dir(dir)? {
            let p = e?.path();
            if p.extension().is_some_and(|x| x == "armory") {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn fast() -> KdfParams {
        KdfParams::with_cost(64, 1)
    }

    // BIP84 and BIP86 published test vectors.
    #[test]
    fn bip84_bip86_vectors() {
        let mut nw = ModernWallet::restore(Network::Bitcoin, "t", ABANDON, "", None, 0).unwrap();
        let w = &mut nw.wallet;
        assert_eq!(w.id, "73c5da0a");
        assert_eq!(
            w.accounts[0].xpub.as_deref(),
            Some(
                "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
            )
        );
        assert_eq!(w.next_receive(0).unwrap().to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(w.next_receive(0).unwrap().to_string(), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
        assert_eq!(w.next_change(0).unwrap().to_string(), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
        let u = w.unlock(None).unwrap();
        let t = w.add_account(&u, AccountKind::Bip86, 0).unwrap();
        assert_eq!(
            w.address(t, 0, 0).unwrap().to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(
            w.address(t, 1, 0).unwrap().to_string(),
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"
        );
        let d = w.public_descriptors(0, 0).unwrap();
        assert!(d[0].starts_with("wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZ"), "{}", d[0]);
        assert!(d[0].contains("/0/*)#") && d[1].contains("/1/*)#"));
    }

    #[test]
    fn encryption_roundtrip_and_tamper() {
        let nw =
            ModernWallet::generate(Network::Regtest, "t", 24, "", Some((b"pw", fast())), None, 1).unwrap();
        assert_eq!(nw.mnemonic.split(' ').count(), 24);
        let json = nw.wallet.to_json().unwrap();
        let mut w = ModernWallet::from_json(&json).unwrap();
        assert!(w.is_encrypted());
        assert!(matches!(w.unlock(Some(b"bad")), Err(ModernError::WrongPassphrase)));
        let u = w.unlock(Some(b"pw")).unwrap();
        assert_eq!(*u.mnemonic().unwrap(), *nw.mnemonic);
        assert!(w.next_receive(0).unwrap().to_string().starts_with("bcrt1q"));
        // Header binding: changing the ID makes decryption fail.
        let mut t = w.clone();
        t.id = "00000000".into();
        assert!(t.unlock(Some(b"pw")).is_err());
        // Remove the passphrase.
        w.reseal(&u, None).unwrap();
        assert!(!w.is_encrypted());
        assert!(w.unlock(None).is_ok());
        let wo = w.watching_only_copy();
        assert!(matches!(wo.unlock(None), Err(ModernError::WatchingOnly)));
        assert_eq!(wo.address(0, 0, 5).unwrap(), w.address(0, 0, 5).unwrap());
    }

    #[test]
    fn tampered_xpub_is_detected() {
        let nw =
            ModernWallet::generate(Network::Bitcoin, "t", 12, "", Some((b"pw", fast())), None, 0).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&nw.wallet.to_json().unwrap()).unwrap();
        let other = ModernWallet::restore(Network::Bitcoin, "x", ABANDON, "", None, 0).unwrap();
        v["accounts"][0]["xpub"] = other.wallet.accounts[0].xpub.clone().unwrap().into();
        let w = ModernWallet::from_json(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(w.unlock(Some(b"pw")), Err(ModernError::Tampered(_))));
        assert!(format!("{:?}", other.wallet).contains("Plaintext(<redacted>)"));
    }

    #[test]
    fn restore_reproduces_wallet() {
        let nw = ModernWallet::generate(Network::Testnet, "a", 12, "extra words", None, None, 0).unwrap();
        let r = ModernWallet::restore(Network::Testnet, "b", &nw.mnemonic, "extra words", None, 0).unwrap();
        assert_eq!(r.wallet.id, nw.wallet.id);
        assert_eq!(r.wallet.address(0, 0, 3).unwrap(), nw.wallet.address(0, 0, 3).unwrap());
        let other = ModernWallet::restore(Network::Testnet, "c", &nw.mnemonic, "", None, 0).unwrap();
        assert_ne!(other.wallet.id, nw.wallet.id);
        assert!(ModernWallet::restore(Network::Testnet, "d", "abandon abandon", "", None, 0).is_err());
    }
}
