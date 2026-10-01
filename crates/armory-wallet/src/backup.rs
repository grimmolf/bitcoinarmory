//! Paper backups, SecurePrint and fragmented (Shamir) backups.
//!
//! * **Modern (v2)**: the BIP39 entropy (16 or 32 bytes) is printed as Easy16 lines
//!   (optionally SecurePrint-masked) next to the recovery words. Fragment sets use random
//!   coefficients and carry a random set ID so fragments of different sets cannot be mixed.
//! * **Legacy (v1.35)**: byte-compatible restore of Armory 0.93 single-sheet (1.35a / 1.35c) and
//!   fragmented backups (spec 02), and creation of legacy single sheets.

use armory_crypto::chain::derive_chaincode;
use armory_crypto::easy16::{self, LineStatus};
use armory_crypto::shamir::{self, Fragment, FragmentIdLine};
use armory_crypto::{hash::hash256, secureprint};
use rand::RngCore;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackupError {
    #[error("line {0}: too many errors to correct (check the line, or it may belong to another backup)")]
    BadLine(usize),
    #[error("expected {expected} data lines, got {got}")]
    LineCount { expected: String, got: usize },
    #[error("invalid SecurePrint code")]
    BadCode,
    #[error("this backup is SecurePrint-protected: the code is required")]
    CodeRequired,
    #[error("invalid fragment ID line {0:?}")]
    BadIdLine(String),
    #[error("fragments belong to different backups (set ID or wallet differs)")]
    MixedSets,
    #[error("fragment #{0} was given twice")]
    DuplicateFragment(u8),
    #[error("{have} fragment(s) given, {need} needed")]
    NotEnoughFragments { have: usize, need: usize },
    #[error("restored data does not match the wallet ID printed on the backup")]
    IdMismatch,
    #[error(transparent)]
    Crypto(#[from] armory_crypto::Error),
}

pub type Result<T> = std::result::Result<T, BackupError>;

/// Printable data lines plus the SecurePrint code (shown on screen, never printed).
#[derive(Debug, Clone)]
pub struct Sheet {
    pub lines: Vec<String>,
    pub code: Option<String>,
}

fn lines_of(data: &[u8]) -> Result<Vec<String>> {
    data.chunks(16).map(|c| Ok(easy16::make_line(c)?)).collect()
}

fn read_lines(lines: &[String]) -> Result<(Zeroizing<Vec<u8>>, usize)> {
    let mut out = Zeroizing::new(Vec::with_capacity(lines.len() * 16));
    let mut fixed = 0;
    for (i, l) in lines.iter().enumerate() {
        let (d, st) = easy16::read_line(l).map_err(|_| BackupError::BadLine(i + 1))?;
        if st == LineStatus::Fixed {
            fixed += 1;
        }
        out.extend_from_slice(&d);
    }
    Ok((out, fixed))
}

fn mask_key(code: &str) -> Result<Zeroizing<Vec<u8>>> {
    if !secureprint::check_code(code) {
        return Err(BackupError::BadCode);
    }
    Ok(secureprint::derive_key(code)?)
}

// ===================================================================== modern (v2)

/// Single sheet for a modern wallet: the BIP39 entropy as 1 (12 words) or 2 (24 words) lines.
pub fn modern_sheet(entropy: &[u8], secure: bool) -> Result<Sheet> {
    if !secure {
        return Ok(Sheet { lines: lines_of(entropy)?, code: None });
    }
    let code = secureprint::create_code(entropy);
    let key = mask_key(&code)?;
    Ok(Sheet { lines: lines_of(&secureprint::mask(&key, entropy)?)?, code: Some(code) })
}

/// Restore BIP39 entropy from sheet lines. Returns the entropy and the number of corrected lines.
pub fn restore_modern_sheet(lines: &[String], code: Option<&str>) -> Result<(Zeroizing<Vec<u8>>, usize)> {
    if lines.len() != 1 && lines.len() != 2 {
        return Err(BackupError::LineCount { expected: "1 or 2".into(), got: lines.len() });
    }
    let (data, fixed) = read_lines(lines)?;
    match code {
        Some(c) => Ok((secureprint::unmask(&mask_key(c)?, &data)?, fixed)),
        None => Ok((data, fixed)),
    }
}

/// ID line of a modern fragment: `flags|M, x, fingerprint[4], set_id[4]` (10 bytes, 20 hex chars).
/// `flags`: 0x40 = format v2, 0x80 = SecurePrint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModernFragmentId {
    pub m: u8,
    pub x: u8,
    pub fingerprint: [u8; 4],
    pub set_id: [u8; 4],
    pub secure: bool,
}

impl ModernFragmentId {
    pub fn to_hex_spaced(&self) -> String {
        let mut b = vec![0x40 | if self.secure { 0x80 } else { 0 } | self.m, self.x];
        b.extend_from_slice(&self.fingerprint);
        b.extend_from_slice(&self.set_id);
        let h = hex(&b);
        (0..5).map(|i| &h[i * 4..i * 4 + 4]).collect::<Vec<_>>().join(" ")
    }

    pub fn parse(s: &str) -> Result<Self> {
        let b = unhex(s)
            .filter(|b| b.len() == 10 && b[0] & 0x40 != 0)
            .ok_or_else(|| BackupError::BadIdLine(s.into()))?;
        let m = b[0] & 0x3f;
        if !(2..=8).contains(&m) || b[1] == 0 {
            return Err(BackupError::BadIdLine(s.into()));
        }
        Ok(Self {
            m,
            x: b[1],
            fingerprint: b[2..6].try_into().unwrap(),
            set_id: b[6..10].try_into().unwrap(),
            secure: b[0] & 0x80 != 0,
        })
    }

    /// Human label, e.g. `3-of set 9f2c41d0 #2`.
    pub fn label(&self) -> String {
        format!("{}-of set {} #{}", self.m, hex(&self.set_id), self.x)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let c: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if c.len() % 2 != 0 || !c.chars().all(|x| x.is_ascii_hexdigit()) {
        return None;
    }
    Some((0..c.len() / 2).map(|i| u8::from_str_radix(&c[2 * i..2 * i + 2], 16).unwrap()).collect())
}

/// One printed fragment.
#[derive(Debug, Clone)]
pub struct PrintedFragment {
    pub id_line: String,
    pub lines: Vec<String>,
    pub label: String,
}

/// M-of-N fragments of the BIP39 entropy with fresh random coefficients and set ID.
pub fn modern_fragments(
    entropy: &[u8],
    fingerprint: [u8; 4],
    m: usize,
    n: usize,
    secure: bool,
) -> Result<(Vec<PrintedFragment>, Option<String>)> {
    if n > 12 {
        return Err(BackupError::LineCount { expected: "at most 12 fragments".into(), got: n });
    }
    let frags = shamir::split_random(entropy, m, n)?;
    let mut set_id = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut set_id);
    let code = secure.then(|| secureprint::create_code(entropy));
    let key = code.as_deref().map(mask_key).transpose()?;
    let mut out = Vec::new();
    for f in &frags {
        let id = ModernFragmentId { m: m as u8, x: *f.x.last().unwrap(), fingerprint, set_id, secure };
        let y = match &key {
            Some(k) => secureprint::mask(k, &f.y)?,
            None => f.y.to_vec(),
        };
        out.push(PrintedFragment { id_line: id.to_hex_spaced(), lines: lines_of(&y)?, label: id.label() });
    }
    Ok((out, code))
}

/// Fragment text as typed or loaded: the ID line and its data lines.
#[derive(Debug, Clone)]
pub struct FragmentInput {
    pub id_line: String,
    pub lines: Vec<String>,
}

/// Parse `ID:` / `F1:`..`F4:` blocks (case-insensitive prefixes; other lines are ignored).
pub fn parse_fragment_text(text: &str) -> Vec<FragmentInput> {
    let mut out: Vec<FragmentInput> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        let Some((key, val)) = line.split_once(':') else { continue };
        let key = key.trim().to_ascii_lowercase();
        if key == "id" {
            out.push(FragmentInput { id_line: val.trim().into(), lines: Vec::new() });
        } else if ["f1", "f2", "f3", "f4"].contains(&key.as_str()) {
            if let Some(f) = out.last_mut() {
                f.lines.push(val.trim().into());
            }
        }
    }
    out
}

/// Restore the BIP39 entropy from modern fragments. Returns the entropy and its fingerprint field.
pub fn restore_modern_fragments(
    inputs: &[FragmentInput],
    code: Option<&str>,
) -> Result<(Zeroizing<Vec<u8>>, [u8; 4])> {
    let mut ids = Vec::new();
    for f in inputs {
        ids.push(ModernFragmentId::parse(&f.id_line)?);
    }
    let first = ids.first().ok_or(BackupError::NotEnoughFragments { have: 0, need: 2 })?.clone();
    let mut seen = std::collections::BTreeSet::new();
    for id in &ids {
        if id.m != first.m || id.set_id != first.set_id || id.fingerprint != first.fingerprint {
            return Err(BackupError::MixedSets);
        }
        if !seen.insert(id.x) {
            return Err(BackupError::DuplicateFragment(id.x));
        }
    }
    let need = first.m as usize;
    if ids.len() < need {
        return Err(BackupError::NotEnoughFragments { have: ids.len(), need });
    }
    let key = if ids.iter().any(|i| i.secure) {
        Some(mask_key(code.ok_or(BackupError::CodeRequired)?)?)
    } else {
        None
    };
    let mut frags = Vec::new();
    let mut nbytes = 0;
    for (f, id) in inputs.iter().zip(&ids) {
        let (y, _) = read_lines(&f.lines)?;
        let y = if id.secure { secureprint::unmask(key.as_ref().unwrap(), &y)? } else { y };
        nbytes = y.len();
        let mut x = vec![0u8; nbytes];
        x[nbytes - 1] = id.x;
        frags.push(Fragment { x, y });
    }
    if frags.iter().any(|f| f.y.len() != nbytes) || !(nbytes == 16 || nbytes == 32) {
        return Err(BackupError::LineCount {
            expected: "1 or 2 lines per fragment".into(),
            got: nbytes / 16,
        });
    }
    Ok((shamir::reconstruct(&frags, need, nbytes)?, first.fingerprint))
}

// ===================================================================== legacy (v1.35)

/// Root key and chain code recovered from a legacy backup.
pub struct LegacyRoot {
    pub root: Zeroizing<[u8; 32]>,
    pub chaincode: [u8; 32],
    /// Number of lines whose checksum had to correct a typing error.
    pub corrected_lines: usize,
}

/// Armory 0.93 single sheet: 2 lines (1.35c, chain code derivable) or 4 lines (1.35a).
pub fn legacy_sheet(root: &[u8; 32], chaincode: &[u8; 32], secure: bool) -> Result<(Sheet, &'static str)> {
    let derivable = derive_chaincode(root) == *chaincode;
    let version = if derivable { "1.35c" } else { "1.35a" };
    let mut secret = Zeroizing::new(root.to_vec());
    secret.extend_from_slice(chaincode);
    let (code, key) = if secure {
        let c = secureprint::create_code(&secret);
        let k = mask_key(&c)?;
        (Some(c), Some(k))
    } else {
        (None, None)
    };
    let enc = |d: &[u8]| -> Result<Vec<u8>> {
        Ok(match &key {
            Some(k) => secureprint::mask(k, d)?,
            None => d.to_vec(),
        })
    };
    let mut lines = lines_of(&enc(root)?)?;
    if !derivable {
        lines.extend(lines_of(&enc(chaincode)?)?);
    }
    Ok((Sheet { lines, code }, version))
}

/// Restore an Armory 0.93 single sheet (2 or 4 lines, optional SecurePrint code).
pub fn restore_legacy_sheet(lines: &[String], code: Option<&str>) -> Result<LegacyRoot> {
    if lines.len() != 2 && lines.len() != 4 {
        return Err(BackupError::LineCount { expected: "2 (1.35c) or 4 (1.35a)".into(), got: lines.len() });
    }
    let (data, fixed) = read_lines(lines)?;
    let key = code.map(mask_key).transpose()?;
    let dec = |d: &[u8]| -> Result<Zeroizing<Vec<u8>>> {
        Ok(match &key {
            Some(k) => secureprint::unmask(k, d)?,
            None => Zeroizing::new(d.to_vec()),
        })
    };
    let root: [u8; 32] = dec(&data[..32])?[..].try_into().unwrap();
    let chaincode =
        if lines.len() == 4 { dec(&data[32..])?[..].try_into().unwrap() } else { derive_chaincode(&root) };
    Ok(LegacyRoot { root: Zeroizing::new(root), chaincode, corrected_lines: fixed })
}

/// Restore an Armory 0.93 fragmented backup (1.35a: 4 lines, 1.35c: 2 lines per fragment).
pub fn restore_legacy_fragments(
    inputs: &[FragmentInput],
    code: Option<&str>,
) -> Result<(LegacyRoot, [u8; 6])> {
    let mut ids = Vec::new();
    for f in inputs {
        ids.push(
            FragmentIdLine::parse_hex(&f.id_line).map_err(|_| BackupError::BadIdLine(f.id_line.clone()))?,
        );
    }
    let first = ids.first().ok_or(BackupError::NotEnoughFragments { have: 0, need: 2 })?.clone();
    let mut seen = std::collections::BTreeSet::new();
    for id in &ids {
        if id.m != first.m || id.wallet_id_bin != first.wallet_id_bin {
            return Err(BackupError::MixedSets);
        }
        if !seen.insert(id.number) {
            return Err(BackupError::DuplicateFragment(id.number));
        }
    }
    let need = first.m as usize;
    if ids.len() < need {
        return Err(BackupError::NotEnoughFragments { have: ids.len(), need });
    }
    let key = if ids.iter().any(|i| i.secure_print) {
        Some(mask_key(code.ok_or(BackupError::CodeRequired)?)?)
    } else {
        None
    };
    let mut frags = Vec::new();
    let mut fixed = 0;
    let nlines = inputs[0].lines.len();
    if nlines != 2 && nlines != 4 || inputs.iter().any(|f| f.lines.len() != nlines) {
        return Err(BackupError::LineCount { expected: "2 or 4 lines per fragment".into(), got: nlines });
    }
    for (f, id) in inputs.iter().zip(&ids) {
        let (y, fx) = read_lines(&f.lines)?;
        fixed += fx;
        let y = if id.secure_print { secureprint::unmask(key.as_ref().unwrap(), &y)? } else { y };
        let n = y.len();
        let mut x = vec![0u8; n];
        x[n - 1] = id.number;
        frags.push(Fragment { x, y });
    }
    let nbytes = nlines * 16;
    let secret = shamir::reconstruct(&frags, need, nbytes)?;
    let root: [u8; 32] = secret[..32].try_into().unwrap();
    let chaincode = if nbytes == 64 { secret[32..].try_into().unwrap() } else { derive_chaincode(&root) };
    Ok((LegacyRoot { root: Zeroizing::new(root), chaincode, corrected_lines: fixed }, first.wallet_id_bin))
}

/// Short checksum shown on modern sheets so a typed-back sheet can be matched to its wallet.
pub fn entropy_tag(entropy: &[u8]) -> String {
    hex(&hash256(entropy)[..2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // spec 02 §9.6 vector A: root aa x32, chain code derived (1.35c), mainnet
    #[test]
    fn legacy_vector_a() {
        let root = [0xaau8; 32];
        let cc = derive_chaincode(&root);
        let (sheet, ver) = legacy_sheet(&root, &cc, false).unwrap();
        assert_eq!(ver, "1.35c");
        assert_eq!(sheet.lines, vec!["rrrr rrrr rrrr rrrr  rrrr rrrr rrrr rrrr  sksi"; 2]);
        let (sec, _) = legacy_sheet(&root, &cc, true).unwrap();
        assert_eq!(sec.code.as_deref(), Some("8rDHqahJzK8"));
        assert_eq!(
            sec.lines,
            s(&[
                "neaj drei hwwo ffih  nkki sdij ajgi nhtf  hhnn",
                "dkhh hhad fisd gjre  ngts nwwe fgns wjhd  juwg"
            ])
        );
        let r = restore_legacy_sheet(&sec.lines, Some("8rDHqahJzK8")).unwrap();
        assert_eq!(*r.root, root);
        assert_eq!(r.chaincode, cc);

        let frag = |id: &str, f1: &str, f2: &str| FragmentInput { id_line: id.into(), lines: s(&[f1, f2]) };
        let f1 = frag(
            "0201 bad4 ab48 0100",
            "sfth rows jfaf ifsh  kros ejed kfrd hewr  dwtt",
            "sioi oadn ihai ajig  odhk ijuk gras oiua  wjuf",
        );
        let f1s = frag(
            "8201 bad4 ab48 0100",
            "jrie ehij fswu hnwk  urew husa khng gtnw  tnjk",
            "oana aksg dukw ofsr  tjeh ttsa dwka oern  fuio",
        );
        let f2 = frag(
            "0202 bad4 ab48 0100",
            "toja hedu airo kiua  dhwu gsfi sogi agfg  taje",
            "uwew wrir kntk tskn  wiad wsks ngru ewjr  fout",
        );
        let f3 = frag(
            "0203 bad4 ab48 0100",
            "jeat afij twhe dwjr  iafj otok uwnk roin  ghdu",
            "kfgf fhwh drjd hudr  fkri dusu enhk ggke  wruk",
        );
        for pair in [vec![f1.clone(), f2.clone()], vec![f3.clone(), f1.clone()], vec![f2.clone(), f3.clone()]]
        {
            let (r, wid) = restore_legacy_fragments(&pair, None).unwrap();
            assert_eq!(*r.root, root);
            assert_eq!(hex(&wid), "bad4ab480100");
        }
        // Mixed SecurePrint and plain rows are allowed, as in Armory.
        assert_eq!(
            *restore_legacy_fragments(&[f1s.clone(), f3.clone()], Some("8rDHqahJzK8")).unwrap().0.root,
            root
        );
        assert!(matches!(restore_legacy_fragments(&[f1s, f3], None), Err(BackupError::CodeRequired)));
        assert!(matches!(
            restore_legacy_fragments(&[f1.clone(), f1], None),
            Err(BackupError::DuplicateFragment(1))
        ));
    }

    // spec 02 §9.6 vector B: root 01..20, chain ff x32 (1.35a, 4 lines)
    #[test]
    fn legacy_vector_b() {
        let root: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        let cc = [0xffu8; 32];
        let (sheet, ver) = legacy_sheet(&root, &cc, false).unwrap();
        assert_eq!(ver, "1.35a");
        assert_eq!(sheet.lines[0], "asad afag ahaj akaw  aear atau aiao ansa  grwt");
        assert_eq!(sheet.lines[2], "nnnn nnnn nnnn nnnn  nnnn nnnn nnnn nnnn  aftr");
        let (sec, _) = legacy_sheet(&root, &cc, true).unwrap();
        assert_eq!(sec.code.as_deref(), Some("hH3LRdpfVBX"));
        assert_eq!(sec.lines[0], "shha swdj jokh sgwn  jgks irad iosu afds  iweu");
        assert_eq!(sec.lines[3], "thdj khsd kkai jwrn  rgio ukkn hjsa taaw  koti");
        let r = restore_legacy_sheet(&sec.lines, Some("hH3LRdpfVBX")).unwrap();
        assert_eq!((*r.root, r.chaincode), (root, cc));
    }

    #[test]
    fn legacy_sheet_typo_is_corrected_and_counted() {
        let root = [0xaau8; 32];
        let mut lines = legacy_sheet(&root, &derive_chaincode(&root), false).unwrap().0.lines;
        lines[1] = lines[1].replacen('r', "t", 1);
        let r = restore_legacy_sheet(&lines, None).unwrap();
        assert_eq!(*r.root, root);
        assert_eq!(r.corrected_lines, 1);
    }

    #[test]
    fn modern_sheet_and_fragments() {
        for len in [16usize, 32] {
            let entropy: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            for secure in [false, true] {
                let sheet = modern_sheet(&entropy, secure).unwrap();
                assert_eq!(sheet.lines.len(), len / 16);
                let (e, _) = restore_modern_sheet(&sheet.lines, sheet.code.as_deref()).unwrap();
                assert_eq!(*e, entropy);

                let fp = [1, 2, 3, 4];
                let (frags, code) = modern_fragments(&entropy, fp, 3, 5, secure).unwrap();
                let text: String = [&frags[4], &frags[0], &frags[2]]
                    .iter()
                    .map(|f| {
                        format!(
                            "ID: {}\n{}\n\n",
                            f.id_line,
                            f.lines
                                .iter()
                                .enumerate()
                                .map(|(i, l)| format!("F{}: {l}", i + 1))
                                .collect::<Vec<_>>()
                                .join("\n")
                        )
                    })
                    .collect();
                let inputs = parse_fragment_text(&text);
                let (e, got_fp) = restore_modern_fragments(&inputs, code.as_deref()).unwrap();
                assert_eq!((*e).clone(), entropy);
                assert_eq!(got_fp, fp);
                assert!(matches!(
                    restore_modern_fragments(&inputs[..2], code.as_deref()),
                    Err(BackupError::NotEnoughFragments { have: 2, need: 3 })
                ));
                // A fragment from another set of the same wallet is refused.
                let (other, _) = modern_fragments(&entropy, fp, 3, 5, secure).unwrap();
                let mut mixed = inputs.clone();
                mixed[0] = FragmentInput { id_line: other[0].id_line.clone(), lines: other[0].lines.clone() };
                assert!(matches!(
                    restore_modern_fragments(&mixed, code.as_deref()),
                    Err(BackupError::MixedSets)
                ));
            }
        }
    }
}
