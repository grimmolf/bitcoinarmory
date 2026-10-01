//! `armory tui`: the full-screen terminal interface (the replacement for Armory's Qt GUI).
//!
//! Screens read wallet files and Bitcoin Core directly for display. Every action either calls the
//! shared operations in [`crate::ops`] or runs the very same `armory` command the CLI runs
//! ([`crate::run_captured`]) on a worker thread, with prompts answered from the TUI's dialogs, so
//! both interfaces behave identically.

mod app;
mod screens;
mod widgets;

use std::path::PathBuf;
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
    let mut app = app::App::new(setup);
    // `init` installs a panic hook that restores the terminal before the panic message.
    let mut terminal = ratatui::try_init().context("cannot initialise the terminal")?;
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    let r = main_loop(&mut terminal, &mut app);
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    r
}

fn main_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut app::App) -> Result<()> {
    while !app.quit {
        terminal.draw(|f| screens::draw(f, app))?;
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
