//! `armory backup` and `armory restore`: paper, SecurePrint and fragmented backups.

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow, bail};
use armory_crypto::chain;
use armory_wallet::LegacyWallet;
use armory_wallet::backup::{self, FragmentInput};
use armory_wallet::modern::{ModernWallet, legacy_network};
use clap::{Args, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::cli_modern::{self as m, KdfArgs};
use crate::context::Context;
use crate::print;

#[derive(Subcommand)]
pub enum BackupCmd {
    /// Digital backup: a copy of the wallet file (encrypted as it is; labels and comments included).
    File {
        id: String,
        /// Destination file or directory.
        dest: PathBuf,
    },
    /// Printable single-sheet backup (recovery words + Easy16 lines, legacy accounts included).
    Paper {
        id: String,
        /// Mask the printed data with a code shown only on screen (SecurePrint).
        #[arg(long)]
        secureprint: bool,
        /// Write the sheet to this file instead of standard output.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// M-of-N fragmented backup of the recovery seed (Shamir secret sharing).
    Fragments {
        id: String,
        #[arg(short, long)]
        m: usize,
        #[arg(short, long)]
        n: usize,
        #[arg(long)]
        secureprint: bool,
        /// Write one file per fragment into this directory instead of standard output.
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
}

#[derive(Args)]
pub struct RestoreCommon {
    /// Read the backup text from this file (default: standard input).
    #[arg(long)]
    file: Option<PathBuf>,
    /// File holding the SecurePrint code.
    #[arg(long)]
    code_file: Option<PathBuf>,
    /// Only check the backup against this wallet ID; nothing is written (PASS/FAIL, exit 4 on FAIL).
    #[arg(long)]
    test: Option<String>,
    /// Add a restored Armory 0.93 wallet to this existing wallet instead of creating a new one.
    #[arg(long)]
    into: Option<String>,
    #[arg(long, default_value = "Restored")]
    label: String,
    /// Ask for the BIP39 passphrase of a modern backup.
    #[arg(long)]
    bip39_passphrase: bool,
    #[arg(long)]
    no_encrypt: bool,
    #[command(flatten)]
    kdf: KdfArgs,
}

#[derive(Subcommand)]
pub enum RestoreCmd {
    /// Restore from a single-sheet backup (modern by default; --legacy for Armory 0.93 sheets).
    Paper {
        /// The sheet is an Armory 0.93 backup (2 lines: 1.35c, 4 lines: 1.35a).
        #[arg(long)]
        legacy: bool,
        /// The sheet was printed with SecurePrint.
        #[arg(long)]
        secureprint: bool,
        /// Which group of lines to use on a sheet with several (1 = seed; Armory 0.93 wallets follow).
        #[arg(long)]
        block: Option<usize>,
        #[command(flatten)]
        common: RestoreCommon,
    },
    /// Restore from fragments (`ID:` and `F1:`..`F4:` lines; modern or Armory 0.93, detected).
    Fragments {
        #[command(flatten)]
        common: RestoreCommon,
    },
}

/// Exit status for a failed backup test.
#[derive(Debug)]
pub struct TestFailed;

impl std::fmt::Display for TestFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("backup test FAILED: the backup does not restore this wallet")
    }
}

impl std::error::Error for TestFailed {}

fn read_input(file: &Option<PathBuf>, what: &str) -> Result<String> {
    if let Some(f) = file {
        return std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()));
    }
    crate::io::read_all(what)
}

fn read_code(common: &RestoreCommon) -> Result<Zeroizing<String>> {
    if let Some(f) = &common.code_file {
        return Ok(Zeroizing::new(std::fs::read_to_string(f)?.trim().to_string()));
    }
    if crate::io::captured() || std::io::stdin().is_terminal() || common.file.is_some() {
        return Ok(Zeroizing::new(crate::io::secret("SecurePrint code: ")?.trim().to_string()));
    }
    bail!("the backup is SecurePrint-protected: pass the code with --code-file")
}

/// Easy16 data lines of a sheet, grouped in blocks (separated by blank or text lines). A
/// `Label:` prefix is removed; a data line has 36 letters (spaces ignored).
fn sheet_blocks(text: &str) -> Vec<Vec<String>> {
    let mut blocks: Vec<Vec<String>> = vec![Vec::new()];
    for l in text.lines() {
        let v = l.split_once(':').map_or(l, |(_, v)| v).trim();
        let compact: Vec<char> = v.chars().filter(|c| *c != ' ').collect();
        if compact.len() == 36 && compact.iter().all(|c| c.is_ascii_alphabetic()) {
            blocks.last_mut().unwrap().push(v.to_string());
        } else if !blocks.last().unwrap().is_empty() {
            blocks.push(Vec::new());
        }
    }
    blocks.retain(|b| !b.is_empty());
    blocks
}

fn pick_block(text: &str, legacy: bool, block: Option<usize>) -> Result<Vec<String>> {
    let blocks = sheet_blocks(text);
    // On a full Armory v2 sheet the seed comes first and Armory 0.93 wallets follow.
    let default = if legacy && text.contains("Seed lines") { 2 } else { 1 };
    let n = block.unwrap_or(default);
    blocks.get(n.wrapping_sub(1)).cloned().ok_or_else(|| anyhow!("no backup lines found (block {n})"))
}

fn indent(lines: &[String]) -> String {
    lines.iter().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
}

pub fn backup(ctx: &Context, json: bool, cmd: BackupCmd) -> Result<()> {
    match cmd {
        BackupCmd::File { id, dest } => {
            let (src, w) = crate::cli_modern::open(ctx, &id)?;
            let dest = if dest.is_dir() { dest.join(w.file_name()) } else { dest };
            if dest.exists() {
                bail!("{} already exists", dest.display());
            }
            armory_wallet::store::atomic_write(&dest, &std::fs::read(&src)?)?;
            print(json, &dest, |d| {
                format!(
                    "Wallet {} copied to {}{}.",
                    w.id,
                    d.display(),
                    if w.is_encrypted() { " (encrypted with its passphrase)" } else { " (NOT encrypted)" }
                )
            });
            return Ok(());
        }
        BackupCmd::Paper { id, secureprint, output } => {
            let (_, w) = m::open(ctx, &id)?;
            let (u, _) = m::unlock(ctx, &w)?;
            let entropy = u.entropy()?;
            let sheet = backup::modern_sheet(&entropy, secureprint)?;
            let mut codes = Vec::new();
            let mut doc = format!(
                "ARMORY PAPER BACKUP\n\nWallet ID:    {}\nName:         {}\nNetwork:      {}\nFormat:       v2, BIP39 entropy ({} words){}\n",
                w.id,
                w.label,
                w.network,
                entropy.len() * 3 / 4,
                if secureprint { ", SecurePrint" } else { "" }
            );
            if !secureprint {
                doc.push_str(&format!("\nRecovery words:\n{}\n", m::numbered(&u.mnemonic()?)));
            }
            doc.push_str(&format!(
                "\nSeed lines (Easy16, each ends with a checksum):\n{}\n",
                indent(&sheet.lines)
            ));
            if let Some(c) = &sheet.code {
                codes.push(("seed".to_string(), c.clone()));
            }
            for (lid, root, cc) in u.legacy_roots()? {
                let (ls, ver) = backup::legacy_sheet(&root, &cc, secureprint)?;
                doc.push_str(&format!(
                    "\nArmory 0.93 wallet {lid} (version {ver}; armory restore paper --legacy):\n{}\n",
                    indent(&ls.lines)
                ));
                if let Some(c) = ls.code {
                    codes.push((format!("Armory 0.93 wallet {lid}"), c));
                }
            }
            if !u.secrets.imported_keys.is_empty() {
                doc.push_str("\nNote: imported keys of migrated wallets are not covered; sweep them or export them separately.\n");
            }
            doc.push_str("\nStore this sheet somewhere safe. Anyone who reads it can spend your funds");
            doc.push_str(if secureprint { " once they also know the SecurePrint code.\n" } else { ".\n" });
            match &output {
                Some(p) => {
                    armory_wallet::store::atomic_write(p, doc.as_bytes())?;
                    noteln!("Paper backup written to {}.", p.display());
                }
                None => outln!("{doc}"),
            }
            for (what, c) in &codes {
                noteln!(
                    "SecurePrint code ({what}): {c}   <- write it down separately; it is NOT on the sheet"
                );
            }
            if json {
                let v = serde_json::json!({ "wallet": w.id, "secureprint_codes": codes });
                noteln!("{v}");
            }
        }
        BackupCmd::Fragments { id, m: need, n, secureprint, output_dir } => {
            let (_, w) = m::open(ctx, &id)?;
            let (u, _) = m::unlock(ctx, &w)?;
            let fp: [u8; 4] = w.master_fingerprint()?.to_bytes();
            let (frags, code) = backup::modern_fragments(&u.entropy()?, fp, need, n, secureprint)?;
            if !u.secrets.legacy_roots.is_empty() {
                noteln!(
                    "warning: fragments cover the recovery seed only, not migrated Armory 0.93 accounts; back those up with `armory backup paper` or sweep them."
                );
            }
            let mut files = Vec::new();
            for f in &frags {
                let body = format!(
                    "ARMORY FRAGMENTED BACKUP: {}\nWallet ID: {}  ({})\nAny {need} of these {n} fragments restore the wallet.\n\nID: {}\n{}\n",
                    f.label,
                    w.id,
                    w.label,
                    f.id_line,
                    f.lines
                        .iter()
                        .enumerate()
                        .map(|(i, l)| format!("F{}: {l}", i + 1))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                match &output_dir {
                    Some(d) => {
                        crate::context::create_private_dir(d)?;
                        let p = d.join(format!(
                            "{}-fragment-{}-of-{n}.txt",
                            w.id,
                            f.label.rsplit('#').next().unwrap_or("x")
                        ));
                        armory_wallet::store::atomic_write(&p, body.as_bytes())?;
                        files.push(p);
                    }
                    None => outln!("{body}\n----------------------------------------- cut here\n"),
                }
            }
            if let Some(c) = &code {
                noteln!(
                    "SecurePrint code: {c}   <- needed with any {need} fragments; it is NOT on the fragments"
                );
            }
            if !files.is_empty() {
                print(json, &files, |f| format!("Wrote {} fragment files.", f.len()));
            }
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct TestResult {
    expected: String,
    restored: String,
    pass: bool,
    corrected_lines: usize,
}

fn finish_test(json: bool, expected: &str, restored: &str, corrected: usize) -> Result<()> {
    let pass = restored.starts_with(expected) && !expected.is_empty();
    let r =
        TestResult { expected: expected.into(), restored: restored.into(), pass, corrected_lines: corrected };
    print(json, &r, |r| {
        format!(
            "{}: backup restores wallet {} (expected {}){}.",
            if r.pass { "PASS" } else { "FAIL" },
            r.restored,
            r.expected,
            if r.corrected_lines > 0 {
                format!("; {} line(s) had a typo that was corrected", r.corrected_lines)
            } else {
                String::new()
            }
        )
    });
    if pass { Ok(()) } else { Err(anyhow!(TestFailed)) }
}

fn restore_modern(
    ctx: &Context,
    json: bool,
    c: &RestoreCommon,
    entropy: &[u8],
    corrected: usize,
    expected_fingerprint: Option<[u8; 4]>,
) -> Result<()> {
    let b39 = m::bip39_pass(c.bip39_passphrase)?;
    let net = ctx.network.bitcoin();
    if let Some(fp) = expected_fingerprint {
        let probe = ModernWallet::restore_entropy(net, "probe", entropy, &b39, None, 0)?;
        if probe.wallet.master_fingerprint()?.to_bytes() != fp {
            bail!("{} (a wrong BIP39 passphrase also causes this)", backup::BackupError::IdMismatch);
        }
    }
    if let Some(expected) = &c.test {
        let probe = ModernWallet::restore_entropy(net, "test", entropy, &b39, None, 0)?;
        return finish_test(json, expected, &probe.wallet.id, corrected);
    }
    if corrected > 0 {
        noteln!(
            "note: {corrected} line(s) had a typo that the checksum corrected; check the wallet ID below."
        );
    }
    let pass = m::new_protection(ctx, c.no_encrypt)?;
    let nw = ModernWallet::restore_entropy(
        net,
        &c.label,
        entropy,
        &b39,
        pass.as_ref().map(|p| (p.as_bytes(), c.kdf.params())),
        m::now(),
    )?;
    let path = m::store_new(ctx, &nw.wallet)?;
    m::show_mnemonic(
        json,
        &m::Created { wallet: m::view(&path, &nw.wallet), mnemonic: nw.mnemonic.to_string() },
    );
    Ok(())
}

fn restore_legacy(ctx: &Context, json: bool, c: &RestoreCommon, r: backup::LegacyRoot) -> Result<()> {
    let lnet = legacy_network(ctx.network.bitcoin());
    let legacy_id = chain::wallet_id_from_root(&r.root, &r.chaincode, lnet.p2pkh_byte())?;
    if let Some(expected) = &c.test {
        return finish_test(json, expected, &legacy_id, r.corrected_lines);
    }
    if r.corrected_lines > 0 {
        noteln!(
            "note: {} line(s) had a typo that the checksum corrected; check the wallet ID.",
            r.corrected_lines
        );
    }
    noteln!("Restored Armory 0.93 wallet {legacy_id}. Compare this ID with the one printed on the backup.");
    let legacy = LegacyWallet::from_root(lnet, &c.label, "", &r.root, Some(r.chaincode), None, 10, m::now())?;
    let (path, mut w, mnemonic, pass, unlocked) = match &c.into {
        Some(id) => {
            let (p, w) = m::open(ctx, id)?;
            let (u, pass) = m::unlock(ctx, &w)?;
            (p, w, None, pass, u)
        }
        None => {
            let pass = m::new_protection(ctx, c.no_encrypt)?;
            let nw = ModernWallet::generate(
                ctx.network.bitcoin(),
                &c.label,
                24,
                "",
                pass.as_ref().map(|p| (p.as_bytes(), c.kdf.params())),
                None,
                m::now(),
            )?;
            let u = nw.wallet.unlock(pass.as_ref().map(|p| p.as_bytes()))?;
            let path = ctx.wallet_dir()?.join(nw.wallet.file_name());
            (path, nw.wallet, Some(nw.mnemonic), pass, u)
        }
    };
    let mut u = unlocked;
    w.migrate_legacy(&mut u, &legacy, None, pass.as_ref().map(|p| p.as_bytes()))?;
    w.save(&path)?;
    match mnemonic {
        Some(mn) => {
            m::show_mnemonic(json, &m::Created { wallet: m::view(&path, &w), mnemonic: mn.to_string() })
        }
        None => print(json, &m::view(&path, &w), m::view_text),
    }
    Ok(())
}

pub fn restore(ctx: &Context, json: bool, cmd: RestoreCmd) -> Result<()> {
    match cmd {
        RestoreCmd::Paper { legacy, secureprint, block, common } => {
            let text = read_input(&common.file, "backup lines")?;
            let lines = pick_block(&text, legacy, block)?;
            let code = if secureprint { Some(read_code(&common)?) } else { None };
            if legacy {
                let r = backup::restore_legacy_sheet(&lines, code.as_deref().map(String::as_str))?;
                restore_legacy(ctx, json, &common, r)
            } else {
                let (e, fixed) = backup::restore_modern_sheet(&lines, code.as_deref().map(String::as_str))?;
                restore_modern(ctx, json, &common, &e, fixed, None)
            }
        }
        RestoreCmd::Fragments { common } => {
            let text = read_input(&common.file, "fragments (ID: and F1:.. lines of each)")?;
            let frags: Vec<FragmentInput> = backup::parse_fragment_text(&text);
            let first = frags.first().ok_or_else(|| anyhow!("no `ID:` line found"))?;
            let id_len = first.id_line.chars().filter(|c| c.is_ascii_hexdigit()).count();
            let secure = frags.iter().any(|f| {
                f.id_line
                    .chars()
                    .find(|c| !c.is_whitespace())
                    .and_then(|c| c.to_digit(16))
                    .is_some_and(|d| d >= 8)
            });
            let code = if secure { Some(read_code(&common)?) } else { None };
            let code = code.as_deref().map(String::as_str);
            if id_len == 16 {
                let (r, _) = backup::restore_legacy_fragments(&frags, code)?;
                restore_legacy(ctx, json, &common, r)
            } else {
                let (e, fp) = backup::restore_modern_fragments(&frags, code)?;
                restore_modern(ctx, json, &common, &e, 0, Some(fp))
            }
        }
    }
}
