//! `armory tui`: the full-screen terminal interface (the replacement for Armory's Qt GUI).
//!
//! Screens read wallet files and Bitcoin Core directly for display. Every action either calls the
//! shared operations in [`crate::ops`] or runs the very same `armory` command the CLI runs
//! ([`crate::run_captured`]) on a worker thread, with prompts answered from the TUI's dialogs, so
//! both interfaces behave identically.

mod app;
mod screens;
mod widgets;

use std::fs::{File, TryLockError};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use ratatui::crossterm::event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind};
use ratatui::crossterm::execute;

use crate::cli_node::NodeArgs;
use crate::context::Context;

pub struct Setup {
    pub ctx: Context,
    pub node: NodeArgs,
    pub datadir: Option<PathBuf>,
    pub passphrase_file: Option<PathBuf>,
}

pub fn run(setup: Setup) -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        anyhow::bail!("the terminal interface needs a terminal; use the commands (see `armory --help`)");
    }
    // Held until return; the OS drops the lock on any exit, a crash included.
    let _lock = lock(&setup.ctx.data_root)?;
    let mut app = app::App::new(setup);
    // `init` installs a panic hook that restores the terminal before the panic message.
    let mut terminal = ratatui::try_init().context("cannot initialise the terminal")?;
    // ratatui's hook restores the terminal on panic. Only the UI thread's panics end the program;
    // a worker's panic is caught and shown as an error, so it must leave the screen alone.
    let restore_hook = std::panic::take_hook();
    let ui_thread = std::thread::current().id();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == ui_thread {
            restore_hook(info);
        }
    }));
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    // https://no-color.org: set and not empty. Read once; modifiers (bold, reverse) stay.
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let r = main_loop(&mut terminal, &mut app, no_color);
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    r
}

/// One TUI per data directory (not per network: Settings switches networks in place).
fn lock(data_root: &Path) -> Result<File> {
    crate::context::create_private_dir(data_root)?;
    let mut opts = File::options();
    opts.create(true).write(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let path = data_root.join("tui.lock");
    let f = opts.open(&path).with_context(|| format!("opening {}", path.display()))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(TryLockError::WouldBlock) => {
            anyhow::bail!("Another Armory TUI is already running on {}", data_root.display())
        }
        Err(TryLockError::Error(e)) => Err(e).with_context(|| format!("locking {}", path.display())),
    }
}

/// Draw a frame; with `no_color`, strip every colour afterwards. A highlighted cell (one with a
/// background) turns reversed so the selection stays visible.
fn draw(f: &mut ratatui::Frame, app: &app::App, no_color: bool) {
    use ratatui::style::{Color, Modifier};
    screens::draw(f, app);
    if no_color {
        for c in &mut f.buffer_mut().content {
            if c.bg != Color::Reset {
                c.modifier |= Modifier::REVERSED;
            }
            (c.fg, c.bg, c.underline_color) = (Color::Reset, Color::Reset, Color::Reset);
        }
    }
}

fn main_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut app::App, no_color: bool) -> Result<()> {
    while !app.quit {
        terminal.draw(|f| draw(f, app, no_color))?;
        if event::poll(Duration::from_millis(120))? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => app.on_key(k),
                Event::Paste(s) => app.on_paste(&s),
                _ => {}
            }
        }
        app.poll();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
