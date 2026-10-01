//! Terminal input and output of commands, with a capture mode for the terminal UI.
//!
//! Commands print through [`outln!`] / [`noteln!`] and read secrets through [`secret`]. Normally that
//! is stdout, stderr and the terminal. Inside [`capture`] (used by the TUI, which runs the very same
//! commands on a worker thread) output goes to a buffer and each prompt is answered from inputs the
//! TUI collected in its own dialogs, matched by the start of the prompt ("New passphrase",
//! "Passphrase for wallet", "Recovery phrase", ...).

use std::cell::RefCell;
use std::io::{BufRead, IsTerminal, Read, Write as _};
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

struct Session {
    out: Zeroizing<String>,
    inputs: Vec<(String, Zeroizing<String>)>,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

/// The log file (`<datadir>/armory.log`), shared by every thread. Nothing read through [`secret`] or
/// [`read_all`] is ever written to it; neither are prompts.
// ponytail: grows without bound and is never rotated; add rotation when someone's log gets big.
static LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);

/// Open the log for appending, created 0600. Failure is not an error: commands run without a log.
pub fn open_log(path: &Path) {
    if let Some(d) = path.parent() {
        let _ = crate::context::create_private_dir(d);
    }
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        o.mode(0o600);
        if let Ok(f) = o.open(path) {
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            *LOG.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
        }
    }
    #[cfg(not(unix))]
    if let Ok(f) = o.open(path) {
        *LOG.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    }
}

/// Append `text` to the log, one timestamped line per line of text. Does nothing without a log.
pub fn log(text: &str) {
    let mut g = LOG.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(f) = g.as_mut() {
        let t = utc(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()));
        for l in text.lines() {
            let _ = writeln!(f, "{t} {l}");
        }
    }
}

/// `2001-09-09T01:46:40Z` from Unix seconds (Hinnant's civil-from-days).
fn utc(secs: u64) -> String {
    let (z, s) = ((secs / 86400) as i64 + 719_468, secs % 86400);
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (d, m) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s % 3600 / 60, s % 60)
}

/// True while running inside [`capture`].
pub fn captured() -> bool {
    SESSION.with(|s| s.borrow().is_some())
}

/// Answers for captured prompts: (start of the prompt, answer).
pub type Inputs = Vec<(String, Zeroizing<String>)>;

/// Run `f` with output captured and prompts answered from `inputs`. Returns what it printed
/// (stdout and stderr interleaved).
pub fn capture<R>(inputs: Inputs, f: impl FnOnce() -> R) -> (R, Zeroizing<String>) {
    SESSION.with(|s| *s.borrow_mut() = Some(Session { out: Zeroizing::new(String::new()), inputs }));
    let r = f();
    let out = SESSION.with(|s| s.borrow_mut().take().map(|s| s.out)).unwrap_or_default();
    (r, out)
}

/// Append to the captured output; false when not capturing.
fn push(text: &str) -> bool {
    SESSION.with(|s| match s.borrow_mut().as_mut() {
        Some(sess) => {
            sess.out.push_str(text);
            true
        }
        None => false,
    })
}

pub fn out(text: &str) {
    if !push(text) {
        use std::io::Write;
        let _ = std::io::stdout().write_all(text.as_bytes());
    }
}

pub fn note(text: &str) {
    for l in text.lines().filter(|l| !l.is_empty()) {
        log(&format!("note {l}"));
    }
    note_unlogged(text);
}

/// Like [`note`] but never logged: for secrets that are generated, not read (SecurePrint codes).
pub fn note_unlogged(text: &str) {
    if !push(text) {
        eprint!("{text}");
    }
}

/// Print a line to stdout (or the capture buffer).
macro_rules! outln {
    ($($t:tt)*) => { $crate::io::out(&format!("{}\n", format_args!($($t)*))) };
}

/// Print a line to stderr (or the capture buffer).
macro_rules! noteln {
    ($($t:tt)*) => { $crate::io::note(&format!("{}\n", format_args!($($t)*))) };
}

/// Like `noteln!` but never logged.
macro_rules! noteln_unlogged {
    ($($t:tt)*) => { $crate::io::note_unlogged(&format!("{}\n", format_args!($($t)*))) };
}

fn next_input(prompt: &str) -> Option<Result<Zeroizing<String>>> {
    SESSION.with(|s| {
        s.borrow().as_ref().map(|sess| {
            match sess.inputs.iter().find(|(k, _)| prompt.starts_with(k.as_str())) {
                Some((_, v)) => Ok(v.clone()),
                None => Err(anyhow::anyhow!("missing input: {}", prompt.trim().trim_end_matches(':'))),
            }
        })
    })
}

/// Read one secret line: the matching input when captured, a hidden prompt on a terminal, otherwise one
/// line of stdin.
pub fn secret(prompt: &str) -> Result<Zeroizing<String>> {
    if let Some(v) = next_input(prompt) {
        return v;
    }
    if std::io::stdin().is_terminal() {
        return Ok(Zeroizing::new(rpassword::prompt_password(prompt)?));
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string()))
}

/// Read a whole text (until end of input): the matching input when captured, otherwise stdin.
pub fn read_all(what: &str) -> Result<String> {
    if let Some(v) = next_input(what) {
        return Ok(v?.to_string());
    }
    if std::io::stdin().is_terminal() {
        noteln!("Type or paste the {what}; finish with Ctrl-D on an empty line.");
    }
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

/// Ask a yes/no question. `yes` skips it; captured runs never ask (the TUI confirms first and
/// passes `yes`).
pub fn confirm(yes: bool, question: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    if captured() || !std::io::stdin().is_terminal() {
        bail!("refusing to continue without confirmation; pass --yes");
    }
    eprint!("{question} [y/N] ");
    let mut l = String::new();
    std::io::stdin().lock().read_line(&mut l)?;
    if l.trim().eq_ignore_ascii_case("y") || l.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("cancelled")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_collects_output_and_feeds_inputs() {
        let (r, out) = capture(vec![("Passphrase".into(), Zeroizing::new("pw".into()))], || {
            outln!("hello {}", 1);
            noteln!("warn");
            let a = secret("Passphrase: ").unwrap();
            let b = secret("Again: ");
            (a.to_string(), b.is_err())
        });
        assert_eq!(r, ("pw".to_string(), true));
        assert_eq!(&*out, "hello 1\nwarn\n");
        assert!(!captured());
        assert!(confirm(true, "?").is_ok());
    }

    #[test]
    fn utc_formats_known_instants() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn log_records_commands_and_notes_but_never_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("armory.log");
        open_log(&log);
        let d = dir.path().display().to_string();
        let args = [
            "--network",
            "regtest",
            "--datadir",
            &d,
            "wallet",
            "create",
            "--label",
            "L",
            "--kdf-memory-mib",
            "1",
            "--kdf-iterations",
            "1",
        ]
        .map(String::from);
        let (r, out) = crate::run_captured(
            &args,
            vec![("New passphrase".into(), Zeroizing::new("hunter2-s3cret".into()))],
        );
        r.unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains(" command wallet create\n"), "{text}");
        assert!(text.contains("Write these words down"), "{text}");
        assert!(!text.contains("hunter2-s3cret") && !text.contains("New passphrase"), "{text}");
        assert!(!text.contains("--datadir") && !text.contains(&d), "argv leaked: {text}");
        assert!(out.contains("Recovery phrase"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
