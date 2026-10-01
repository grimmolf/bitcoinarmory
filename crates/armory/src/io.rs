//! Terminal input and output of commands, with a capture mode for the terminal UI.
//!
//! Commands print through [`outln!`] / [`noteln!`] and read secrets through [`secret`]. Normally that
//! is stdout, stderr and the terminal. Inside [`capture`] (used by the TUI, which runs the very same
//! commands on a worker thread) output goes to a buffer and each prompt is answered from inputs the
//! TUI collected in its own dialogs, matched by the start of the prompt ("New passphrase",
//! "Passphrase for wallet", "Recovery phrase", ...).

use std::cell::RefCell;
use std::io::{BufRead, IsTerminal, Read};

use anyhow::{Result, bail};
use zeroize::Zeroizing;

struct Session {
    out: Zeroizing<String>,
    inputs: Vec<(String, Zeroizing<String>)>,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
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
}
