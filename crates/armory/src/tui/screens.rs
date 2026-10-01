//! The screens: what they show, their keys and the dialogs behind each action.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use armory_node::core::Core;
use armory_wallet::modern::{AccountKind, ModernError, ModernWallet};
use armory_wallet::sign;
use bitcoin::psbt::Psbt;
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Cell, List, ListItem, ListState, Paragraph, Row, Table, TableState, Tabs, Wrap,
};
use zeroize::Zeroizing;

use super::app::{App, Reply, net_name};
use super::widgets::{Form, Modal, Values, choice, multi, secret, text, toggle};
use crate::cli_misc::{AddressBook, PaymentUri, qr_text};
use crate::cli_tx::{FeeArgs, summary_text, write_psbt};
use crate::context::{Context, Network};
use crate::io::Inputs;
use crate::ops::{self, Prepared, SendSpec};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Overview,
    Wallets,
    Receive,
    Send,
    History,
    Offline,
    Lockboxes,
    Backup,
    Tools,
    Settings,
}

const TABS: [(Tab, &str); 10] = [
    (Tab::Overview, "Overview"),
    (Tab::Wallets, "Wallets"),
    (Tab::Receive, "Receive"),
    (Tab::Send, "Send"),
    (Tab::History, "History"),
    (Tab::Offline, "Offline"),
    (Tab::Lockboxes, "Lockboxes"),
    (Tab::Backup, "Backup"),
    (Tab::Tools, "Tools"),
    (Tab::Settings, "Settings"),
];

impl Tab {
    fn index(self) -> usize {
        TABS.iter().position(|(t, _)| *t == self).unwrap_or(0)
    }
    pub fn next(self) -> Tab {
        TABS[(self.index() + 1) % TABS.len()].0
    }
    pub fn prev(self) -> Tab {
        TABS[(self.index() + TABS.len() - 1) % TABS.len()].0
    }
    pub fn from_digit(c: char) -> Option<Tab> {
        let d = c.to_digit(10)? as usize;
        Some(TABS[if d == 0 { 9 } else { d - 1 }].0)
    }
}

/// A transaction loaded on the Offline screen.
pub struct OfflineTx {
    pub path: PathBuf,
    pub psbt: Psbt,
    pub armory_format: bool,
    pub summary: String,
}

/// Per-screen selections.
#[derive(Default)]
pub struct State {
    pub account: usize,
    pub addr_sel: usize,
    pub hist_sel: usize,
    pub coins: bool,
    pub coin_sel: usize,
    pub lb_sel: usize,
    pub book_sel: usize,
    pub book: Vec<crate::cli_misc::BookEntry>,
    pub offline: Option<OfflineTx>,
    pub last_send: Option<String>,
    /// Coins marked for coin control (`TXID:VOUT`).
    pub marked: std::collections::BTreeSet<String>,
}

/// Keep selections inside their lists.
pub fn clamp(app: &mut App) {
    let n_acct = app.wallet().map(|w| w.accounts.len()).unwrap_or(0);
    let n_addr = receive_addresses(app).len();
    let (n_hist, n_coin) = app.wallet_data().map(|d| (d.history.len(), d.utxos.len())).unwrap_or((0, 0));
    let n_lb = app.lockboxes.len();
    app.screens.book = AddressBook::load(&app.ctx).map(|b| b.entries).unwrap_or_default();
    let n_book = app.screens.book.len();
    let s = &mut app.screens;
    s.account = s.account.min(n_acct.saturating_sub(1));
    s.addr_sel = s.addr_sel.min(n_addr.saturating_sub(1));
    s.hist_sel = s.hist_sel.min(n_hist.saturating_sub(1));
    s.coin_sel = s.coin_sel.min(n_coin.saturating_sub(1));
    s.lb_sel = s.lb_sel.min(n_lb.saturating_sub(1));
    s.book_sel = s.book_sel.min(n_book.saturating_sub(1));
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn input(key: &str, v: Zeroizing<String>) -> (String, Zeroizing<String>) {
    (key.to_string(), v)
}

pub fn btc(sats: i64) -> String {
    let sign = if sats < 0 { "-" } else { "" };
    let a = sats.unsigned_abs();
    format!("{sign}{}.{:08}", a / 100_000_000, a % 100_000_000)
}

/// `YYYY-MM-DD HH:MM` (UTC) for a unix time.
pub fn fmt_time(t: u64) -> String {
    if t == 0 {
        return "-".into();
    }
    let days = (t / 86_400) as i64;
    let secs = t % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, secs % 3600 / 60)
}

fn panel(title: &str) -> Block<'static> {
    Block::bordered().border_type(BorderType::Rounded).title(format!(" {title} "))
}

fn hl() -> Style {
    Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
}

fn move_sel(sel: &mut usize, len: usize, k: &KeyEvent) -> bool {
    match k.code {
        KeyCode::Down => *sel = (*sel + 1).min(len.saturating_sub(1)),
        KeyCode::Up => *sel = sel.saturating_sub(1),
        KeyCode::PageDown => *sel = (*sel + 15).min(len.saturating_sub(1)),
        KeyCode::PageUp => *sel = sel.saturating_sub(15),
        KeyCode::Home => *sel = 0,
        KeyCode::End => *sel = len.saturating_sub(1),
        _ => return false,
    }
    true
}

// ====================================================================== layout

pub fn draw(f: &mut Frame, app: &App) {
    let [head, ctx_line, body, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(2),
    ])
    .areas(f.area());
    let titles: Vec<Line> =
        TABS.iter().enumerate().map(|(i, (_, t))| Line::from(format!("{} {t}", (i + 1) % 10))).collect();
    f.render_widget(
        Tabs::new(titles)
            .select(app.tab.index())
            .highlight_style(Style::new().fg(Color::Black).bg(Color::Cyan).bold())
            .divider("│"),
        head,
    );
    let node = match &app.node_status {
        None => Span::raw("node: …").dim(),
        Some(Ok(s)) => Span::raw(format!(
            "Core {} · {} blocks{}",
            s.subversion.trim_matches('/'),
            s.blocks,
            if s.initial_block_download { " · syncing" } else { "" }
        ))
        .fg(Color::Green),
        Some(Err(_)) => Span::raw("node: not connected").fg(Color::Red),
    };
    let wallet = match app.wallet() {
        Some(w) => format!("wallet: {} ({})  [ ] switch", w.label, w.id),
        None => "no wallet".into(),
    };
    f.render_widget(
        Line::from(vec![
            Span::raw(format!(" Armory · {} · ", net_name(app.ctx.network))).bold(),
            Span::raw(wallet).fg(Color::Yellow),
            Span::raw(" · "),
            node,
        ]),
        ctx_line,
    );
    match app.tab {
        Tab::Overview => draw_overview(f, body, app),
        Tab::Wallets => draw_wallets(f, body, app),
        Tab::Receive => draw_receive(f, body, app),
        Tab::Send => draw_send(f, body, app),
        Tab::History => draw_history(f, body, app),
        Tab::Offline => draw_offline(f, body, app),
        Tab::Lockboxes => draw_lockboxes(f, body, app),
        Tab::Backup => draw_text_screen(f, body, "Backup and restore", BACKUP_TEXT),
        Tab::Tools => draw_tools(f, body, app),
        Tab::Settings => draw_settings(f, body, app),
    }
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][app.tick % 10];
    let status = if !app.busy.is_empty() {
        Line::from(format!(" {spinner} {}…", app.busy.join(", "))).fg(Color::Cyan)
    } else if app.status.1 {
        Line::from(format!(" {}", app.status.0)).fg(Color::Red)
    } else {
        Line::from(format!(" {}", app.status.0)).fg(Color::Green)
    };
    let [s1, s2] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(foot);
    f.render_widget(status, s1);
    f.render_widget(
        Line::from(format!(" {}  ·  ? help  : command  r refresh  q quit", keys_hint(app.tab))).dim(),
        s2,
    );
    for m in &app.modals {
        match m {
            Modal::Form(x) => x.draw(f, f.area()),
            Modal::View(x) => x.draw(f, f.area()),
            Modal::Confirm(x) => x.draw(f, f.area()),
        }
    }
}

fn keys_hint(t: Tab) -> &'static str {
    match t {
        Tab::Overview => "↑↓ select wallet  Enter details  s sync",
        Tab::Wallets => "c create  R restore  I import  m migrate  s sync  e rename  p passphrase  S seed  …",
        Tab::Receive => "n new address  a account  Enter QR  y copy  l label  u payment request",
        Tab::Send => "n new payment  u pay a bitcoin: link  Enter pay contact  b add contact  d delete",
        Tab::History => {
            "v transactions/coins  Enter details  y copy  c comment  f bump fee  x abandon  e CSV"
        }
        Tab::Offline => "o open  p paste  s sign  b broadcast  r raw  c convert  m combine  v save as",
        Tab::Lockboxes => "n create  k my key  i import  e export  s sync  a address  b balance  p spend",
        Tab::Backup => "p paper  f fragments  d file copy  t/T test  R/F restore",
        Tab::Tools => "s sign  v verify  b verify block  k sweep key  i key info  d decode  u URI  l legacy",
        Tab::Settings => "n network  c node connection  t test connection  a about",
    }
}

pub fn help(t: Tab) -> String {
    let common = "\nEverywhere:\n  1-9, 0 / Tab   switch screen\n  [ ] or w W    previous / next wallet\n  r, F5         refresh from Bitcoin Core\n  :             run any armory command (same as the command line)\n  ?             this help\n  q, Ctrl-C     quit\n\nIn dialogs: Enter next field / submit, Tab move, Space or ←→ change, Ctrl-S submit, Esc cancel.\nPasting works in every text field.";
    let s = match t {
        Tab::Overview => {
            "Overview\n  ↑↓     select wallet\n  Enter  open on the Wallets screen\n  s      let Bitcoin Core watch the selected wallet (sync)"
        }
        Tab::Wallets => {
            "Wallets\n  ↑↓  select\n  c   create a wallet (new recovery words)\n  R   restore from recovery words\n  I   import a wallet file (e.g. a watching-only copy)\n  m   migrate an Armory 0.93 wallet\n  e   rename\n  p   set / change / remove passphrase\n  A   add a SegWit or Taproot account\n  s   sync with Bitcoin Core (import descriptors, rescan)\n  d   watch-only descriptors     D  private descriptors\n  k   check the wallet\n  S   show recovery words        X  export private keys\n  E   export a watching-only copy\n  L   sweep migrated Armory 0.93 funds into the SegWit account\n  x   remove the wallet"
        }
        Tab::Receive => {
            "Receive\n  n      new receive address\n  a      next account\n  ↑↓     select an address\n  Enter  show QR code\n  y      copy the address to the clipboard\n  l      label the selected address\n  u      payment request (bitcoin: link with amount) and QR"
        }
        Tab::Send => {
            "Send\n  n      new payment (several recipients, send max, fee, unsigned PSBT for offline signing)\n  u      pay a bitcoin: link\n  ↑↓     select a contact;  Enter pays the selected contact\n  b      add or relabel a contact   d  delete it\n\nBitcoin Core selects coins; Armory checks the result against what you asked for,\nshows it, and signs only after you confirm."
        }
        Tab::History => {
            "History\n  v      switch between transactions and coins (UTXOs)\n  Space  (coins) mark a coin;  s  pay from the marked coins (coin control)\n  y      copy the transaction ID\n  ↑↓     select\n  Enter  details\n  c      comment on a transaction\n  f      raise the fee of an unconfirmed transaction (RBF)\n  x      abandon an unconfirmed transaction\n  e      export the history as CSV"
        }
        Tab::Offline => {
            "Offline transactions (PSBT, and Armory 0.93 TXSIGCOLLECT files)\n  o  open a file          p  paste a transaction and save it\n  s  sign with the selected wallet (works without a node)\n  b  broadcast (finalizes first)      r  broadcast a raw transaction (hex)\n  c  convert PSBT <-> Armory 0.93 format\n  m  combine signatures from several files (multisig)\n  v  save the loaded transaction as a PSBT file"
        }
        Tab::Lockboxes => {
            "Lockboxes (multisig)\n  ↑↓  select\n  k   export the selected wallet's cosigner key\n  n   create an M-of-N lockbox from cosigner keys\n  i   import a lockbox file, multisigs.txt or LOCKBOX block\n  e   export the lockbox file for the cosigners\n  s   sync with Bitcoin Core    a  next deposit address\n  b   balance                   u  coins\n  p   build a spend (PSBT) for the cosigners to sign on the Offline screen"
        }
        Tab::Backup => {
            "Backup\n  p  paper backup of the selected wallet (optionally SecurePrint)\n  f  fragmented backup (M of N)\n  d  digital backup: a copy of the wallet file\n  t  test a paper backup     T  test fragments\n  R  restore from a paper backup (modern or Armory 0.93)\n  F  restore from fragments"
        }
        Tab::Tools => {
            "Tools\n  s  sign a message          v  verify a signature\n  b  verify an Armory signed-message block\n  k  sweep a private key into the selected wallet\n  i  key information (addresses, WIF) for a private key\n  d  decode a raw transaction\n  u  decode a bitcoin: link\n  l  list Armory 0.93 wallet files (use : for the legacy commands)"
        }
        Tab::Settings => {
            "Settings\n  n  network\n  c  Bitcoin Core connection (address, cookie, user, data directory)\n  t  test the connection\n  a  about Armory"
        }
    };
    format!("{s}\n{common}")
}

pub fn on_key(app: &mut App, k: KeyEvent) -> Result<()> {
    match app.tab {
        Tab::Overview => overview_key(app, k),
        Tab::Wallets => wallets_key(app, k),
        Tab::Receive => receive_key(app, k),
        Tab::Send => send_key(app, k),
        Tab::History => history_key(app, k),
        Tab::Offline => offline_key(app, k),
        Tab::Lockboxes => lockbox_key(app, k),
        Tab::Backup => backup_key(app, k),
        Tab::Tools => tools_key(app, k),
        Tab::Settings => settings_key(app, k),
    }
}

// ====================================================================== overview

fn draw_overview(f: &mut Frame, area: Rect, app: &App) {
    let [top, bottom] = Layout::vertical([Constraint::Length(7), Constraint::Min(3)]).areas(area);
    let node_text = match &app.node_status {
        None => Text::raw("Connecting to Bitcoin Core…"),
        Some(Ok(s)) => {
            let mut t = vec![
                Line::from(format!("Bitcoin Core {} on {}", s.subversion.trim_matches('/'), s.chain)),
                Line::from(format!(
                    "Blocks {} / headers {}  ({:.2}% verified)",
                    s.blocks,
                    s.headers,
                    s.verification_progress * 100.0
                )),
            ];
            if s.initial_block_download {
                t.push(Line::from("Still syncing: balances may be incomplete.").fg(Color::Yellow));
            }
            if s.pruned {
                t.push(
                    Line::from("Pruned node: restoring old wallets needs an unpruned node.")
                        .fg(Color::Yellow),
                );
            }
            if s.version < armory_node::core::RECOMMENDED_VERSION {
                t.push(
                    Line::from("This Core release is end-of-life; 29.0 or newer is recommended.")
                        .fg(Color::Yellow),
                );
            }
            Text::from(t)
        }
        Some(Err(e)) => Text::from(vec![
            Line::from("Not connected to Bitcoin Core.").fg(Color::Red),
            Line::from(e.clone()),
            Line::from(
                "Wallets, backups and offline signing work without a node. Settings (0) → c to configure.",
            ),
        ]),
    };
    f.render_widget(Paragraph::new(node_text).block(panel("Node")).wrap(Wrap { trim: true }), top);
    let mut total = (0i64, 0i64);
    let rows: Vec<Row> = app
        .wallets
        .iter()
        .map(|(_, w)| {
            let d = app.data.get(&w.id);
            let (conf, pend) = match d.and_then(|d| d.balances.as_ref()) {
                Some(b) => {
                    total.0 += b.confirmed;
                    total.1 += b.pending;
                    (btc(b.confirmed), btc(b.pending))
                }
                None if d.is_some() => ("not synced".into(), String::new()),
                None => ("…".into(), String::new()),
            };
            Row::new(vec![
                Cell::from(w.label.clone()),
                Cell::from(w.id.clone()),
                Cell::from(protection(w)),
                Cell::from(w.accounts.len().to_string()),
                Cell::from(conf),
                Cell::from(pend),
            ])
        })
        .collect();
    let mut st = TableState::default().with_selected(Some(app.wsel));
    let table = Table::new(
        rows,
        [
            Constraint::Min(16),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(16),
        ],
    )
    .header(Row::new(vec!["Wallet", "ID", "Protection", "Accounts", "Confirmed BTC", "Pending BTC"]).bold())
    .row_highlight_style(hl())
    .block(panel(&format!("Wallets · total {} BTC confirmed, {} pending", btc(total.0), btc(total.1))));
    if app.wallets.is_empty() {
        f.render_widget(
            Paragraph::new("No wallets on this network yet.\n\nGo to Wallets (2) and press c to create one, R to restore from recovery words, or m to migrate an Armory 0.93 wallet.")
                .block(panel("Wallets"))
                .wrap(Wrap { trim: true }),
            bottom,
        );
    } else {
        f.render_stateful_widget(table, bottom, &mut st);
    }
}

fn protection(w: &ModernWallet) -> &'static str {
    if w.is_watching_only() {
        "watching-only"
    } else if w.is_encrypted() {
        "encrypted"
    } else {
        "unencrypted"
    }
}

fn overview_key(app: &mut App, k: KeyEvent) -> Result<()> {
    let n = app.wallets.len();
    if move_sel(&mut app.wsel, n, &k) {
        clamp(app);
        return Ok(());
    }
    match k.code {
        KeyCode::Enter => app.tab = Tab::Wallets,
        KeyCode::Char('s') => sync_form(app)?,
        _ => {}
    }
    Ok(())
}

// ====================================================================== wallets

fn draw_wallets(f: &mut Frame, area: Rect, app: &App) {
    let [left, right] = Layout::horizontal([Constraint::Length(32), Constraint::Min(30)]).areas(area);
    let items: Vec<ListItem> =
        app.wallets.iter().map(|(_, w)| ListItem::new(format!("{}  {}", w.id, w.label))).collect();
    let mut st = ListState::default().with_selected(Some(app.wsel));
    f.render_stateful_widget(List::new(items).block(panel("Wallets")).highlight_style(hl()), left, &mut st);
    let body = match app.wallets.get(app.wsel) {
        Some((p, w)) => {
            let mut s = crate::cli_modern::view_text(&crate::cli_modern::view(p, w));
            if !w.description.is_empty() {
                s.push_str(&format!("\nDescription: {}", w.description));
            }
            s.push_str(&format!(
                "\nCreated:     {}\nBirthday:    {}",
                fmt_time(w.created),
                if w.birthday == 0 { "unknown (restored)".into() } else { fmt_time(w.birthday) }
            ));
            if let Some(d) = app.data.get(&w.id) {
                match (&d.balances, &d.error) {
                    (Some(b), _) => s.push_str(&format!(
                        "\n\nBalance:     {} BTC confirmed\n             {} BTC pending\n             {} BTC immature",
                        btc(b.confirmed),
                        btc(b.pending),
                        btc(b.immature)
                    )),
                    (None, Some(e)) => s.push_str(&format!(
                        "\n\nBitcoin Core: {e}\nPress s to let Core watch this wallet."
                    )),
                    _ => {}
                }
            }
            s
        }
        None => "No wallets yet.\n\n  c  create a wallet\n  R  restore from recovery words\n  m  migrate an Armory 0.93 wallet\n  F  (Backup screen) restore from fragments".into(),
    };
    f.render_widget(Paragraph::new(body).block(panel("Details")).wrap(Wrap { trim: false }), right);
}

/// Validate a new-passphrase pair; None with "unencrypted".
fn new_pass(v: &Values, pass: usize, repeat: usize, unencrypted: usize) -> Result<Option<Zeroizing<String>>> {
    if v.flag(unencrypted) {
        if !v.raw(pass).is_empty() {
            bail!("you ticked \"store unencrypted\" but typed a passphrase");
        }
        return Ok(None);
    }
    if v.raw(pass).is_empty() {
        bail!("choose a passphrase (or tick \"store unencrypted\", not recommended)");
    }
    if v.raw(pass) != v.raw(repeat) {
        bail!("the passphrases do not match");
    }
    Ok(Some(v.secret(pass)))
}

fn create_form(app: &mut App) {
    app.push_form(
        Form::new(
            "Create a wallet",
            vec![
                text("Name"),
                text("Description"),
                choice("Recovery words", &["24", "12"]),
                toggle("Taproot account too"),
                secret("Passphrase"),
                secret("Repeat passphrase"),
                toggle("Store unencrypted"),
                secret("BIP39 passphrase").help("Optional \"25th word\". Without it the words alone restore the wallet; with it you need both."),
                text("Extra entropy").help("Optional: dice rolls or other randomness, mixed into the system's random numbers."),
            ],
            |app, v| {
                let name = v.opt(0).ok_or_else(|| anyhow!("give the wallet a name"))?;
                let pass = new_pass(v, 4, 5, 6)?;
                let mut a = args(&["wallet", "create", "--label", &name, "--description", v.str(1), "--words", v.str(2)]);
                if v.flag(3) {
                    a.push("--taproot".into());
                }
                let mut inputs: Inputs = Vec::new();
                match pass {
                    Some(p) => inputs.push(input("New passphrase", p)),
                    None => a.push("--no-encrypt".into()),
                }
                if !v.raw(7).is_empty() {
                    a.push("--bip39-passphrase".into());
                    inputs.push(input("BIP39 passphrase", v.secret(7)));
                }
                if let Some(e) = v.opt(8) {
                    a.extend(["--extra-entropy".into(), e]);
                }
                app.command("New wallet: write down the recovery words", a, inputs, true);
                Ok(())
            },
        )
        .intro("A new BIP39 recovery phrase is generated. Write the words on paper: they restore the wallet\nin Armory and in any BIP39/BIP84 wallet. The passphrase protects the wallet file on this computer."),
    );
}

fn restore_words_form(app: &mut App) {
    app.push_form(Form::new(
        "Restore from recovery words",
        vec![
            text("Name").with("Restored"),
            multi("Recovery words"),
            secret("BIP39 passphrase").help("Only if the wallet was created with a \"25th word\"."),
            toggle("Taproot account too"),
            secret("Passphrase"),
            secret("Repeat passphrase"),
            toggle("Store unencrypted"),
        ],
        |app, v| {
            let words = v.str(1).split_whitespace().collect::<Vec<_>>().join(" ");
            if words.is_empty() {
                bail!("type the recovery words");
            }
            let pass = new_pass(v, 4, 5, 6)?;
            let mut a = args(&["wallet", "restore", "--label", v.str(0)]);
            let mut inputs: Inputs = vec![input("Recovery phrase", Zeroizing::new(words))];
            if v.flag(3) {
                a.push("--taproot".into());
            }
            if !v.raw(2).is_empty() {
                a.push("--bip39-passphrase".into());
                inputs.push(input("BIP39 passphrase", v.secret(2)));
            }
            match pass {
                Some(p) => inputs.push(input("New passphrase", p)),
                None => a.push("--no-encrypt".into()),
            }
            app.command("Restore wallet", a, inputs, true);
            Ok(())
        },
    ));
}

fn migrate_form(app: &mut App) {
    let legacy: Vec<String> = crate::app::list_wallets(&app.ctx)
        .map(|v| v.iter().map(|f| format!("{} ({})", f.wallet.id(), f.wallet.label())).collect())
        .unwrap_or_default();
    let hint = if legacy.is_empty() {
        "Path of an Armory 0.93 .wallet file (e.g. ~/.armory/armory_XXXX_.wallet).".to_string()
    } else {
        format!("Wallet ID or .wallet path. Imported legacy wallets: {}", legacy.join(", "))
    };
    let into = app.wallet().map(|w| w.id.clone());
    app.push_form(
        Form::new(
            "Migrate an Armory 0.93 wallet",
            vec![
                text("Legacy wallet").help(&hint),
                secret("Its passphrase").help("Leave empty if the old wallet is not encrypted."),
                toggle("Add to selected wallet").help("Add as an account of the selected wallet instead of creating a new one."),
                text("New wallet name").help("Default: the old wallet's name."),
                secret("New passphrase"),
                secret("Repeat passphrase"),
                toggle("Store unencrypted"),
            ],
            move |app, v| {
                let legacy = v.opt(0).ok_or_else(|| anyhow!("which legacy wallet?"))?;
                let legacy = shellexpand(&legacy);
                let mut a = args(&["wallet", "migrate", &legacy]);
                let mut inputs: Inputs = Vec::new();
                if !v.raw(1).is_empty() {
                    inputs.push(input("Passphrase of legacy wallet", v.secret(1)));
                }
                if v.flag(2) {
                    let id = into.clone().ok_or_else(|| anyhow!("no wallet selected"))?;
                    a.extend(["--into".into(), id]);
                    let w = app.require_wallet()?;
                    app.wallet_command("Migrate", &w, a, inputs, true);
                    return Ok(());
                }
                if let Some(l) = v.opt(3) {
                    a.extend(["--label".into(), l]);
                }
                match new_pass(v, 4, 5, 6)? {
                    Some(p) => inputs.push(input("New passphrase", p)),
                    None => a.push("--no-encrypt".into()),
                }
                app.command("Migrated wallet: write down the new recovery words", a, inputs, true);
                Ok(())
            },
        )
        .intro("The old wallet's keys become a legacy account of a modern wallet. The old file is not changed.\nAfterwards, sync the wallet and sweep the old funds (L) into the SegWit account."),
    );
}

fn shellexpand(p: &str) -> String {
    match (p.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(h)) => PathBuf::from(h).join(rest).display().to_string(),
        _ => p.to_string(),
    }
}

fn sync_form(app: &mut App) -> Result<()> {
    let w = app.require_wallet()?;
    let id = w.id.clone();
    app.push_form(
        Form::new(
            &format!("Sync {} with Bitcoin Core", w.label),
            vec![
                choice("Rescan", &["from the wallet birthday", "no rescan", "from a date"]),
                text("Date (YYYY-MM-DD)"),
            ],
            move |app, v| {
                let mut a = args(&["wallet", "sync", &id]);
                match v.str(0) {
                    "no rescan" => a.push("--no-rescan".into()),
                    "from a date" => {
                        let t = parse_date(v.str(1))?;
                        a.extend(["--rescan-from".into(), t.to_string()]);
                    }
                    _ => {}
                }
                app.command("Sync", a, Vec::new(), false);
                Ok(())
            },
        )
        .intro("Bitcoin Core watches the wallet's addresses (watch-only, no private keys).\nA rescan finds past transactions; it can take a while on mainnet."),
    );
    Ok(())
}

fn parse_date(s: &str) -> Result<u64> {
    let p: Vec<i64> = s
        .split('-')
        .map(|x| x.trim().parse())
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow!("date as YYYY-MM-DD"))?;
    let [y, m, d] = p[..] else { bail!("date as YYYY-MM-DD") };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || y < 2009 {
        bail!("date as YYYY-MM-DD");
    }
    // days-from-civil
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(((era * 146_097 + doe - 719_468) * 86_400) as u64)
}

fn wallets_key(app: &mut App, k: KeyEvent) -> Result<()> {
    let n = app.wallets.len();
    if move_sel(&mut app.wsel, n, &k) {
        clamp(app);
        return Ok(());
    }
    match k.code {
        KeyCode::Char('c') => create_form(app),
        KeyCode::Char('I') => app.push_form(Form::new(
            "Import a wallet file",
            vec![
                text("File")
                    .with(&format!("{}/", home_dir()))
                    .help("A .armory file, e.g. a watching-only copy made on the offline computer."),
                toggle("Replace if present"),
            ],
            |app, v| {
                let mut a = args(&["wallet", "import", &shellexpand(v.str(0))]);
                if v.flag(1) {
                    a.push("--replace".into());
                }
                app.command("Import", a, Vec::new(), true);
                Ok(())
            },
        )),
        KeyCode::Char('R') => restore_words_form(app),
        KeyCode::Char('m') => migrate_form(app),
        KeyCode::Char('s') => sync_form(app)?,
        KeyCode::Char('e') => {
            let w = app.require_wallet()?;
            let id = w.id.clone();
            app.push_form(Form::new(
                "Rename wallet",
                vec![text("Name").with(&w.label), text("Description").with(&w.description)],
                move |app, v| {
                    let name = v.opt(0).ok_or_else(|| anyhow!("the name cannot be empty"))?;
                    app.command(
                        "Rename",
                        args(&["wallet", "rename", &id, "--label", &name, "--description", v.str(1)]),
                        Vec::new(),
                        false,
                    );
                    Ok(())
                },
            ));
        }
        KeyCode::Char('p') => {
            let w = app.require_wallet()?;
            if w.is_watching_only() {
                bail!("a watching-only wallet has no secrets to protect");
            }
            let options: &[&str] = if w.is_encrypted() { &["change", "remove"] } else { &["set"] };
            app.push_form(Form::new(
                "Wallet passphrase",
                vec![choice("Action", options), secret("New passphrase"), secret("Repeat passphrase")],
                move |app, v| {
                    let action = v.str(0).to_string();
                    let mut inputs: Inputs = Vec::new();
                    if action != "remove" {
                        if v.raw(1).is_empty() || v.raw(1) != v.raw(2) {
                            bail!("type the new passphrase twice");
                        }
                        inputs.push(input("New passphrase", v.secret(1)));
                    }
                    let a = args(&["wallet", "passphrase", &w.id, &action]);
                    app.wallet_command("Passphrase", &w, a, inputs, false);
                    Ok(())
                },
            ));
        }
        KeyCode::Char('A') => {
            let w = app.require_wallet()?;
            app.push_form(Form::new(
                "Add an account",
                vec![choice("Type", &["segwit", "taproot"]), text("Account number").with("0")],
                move |app, v| {
                    let a = args(&["wallet", "add-account", &w.id, v.str(0), "--index", v.str(1)]);
                    app.wallet_command("Add account", &w, a, Vec::new(), true);
                    Ok(())
                },
            ));
        }
        KeyCode::Char('d') => {
            let w = app.require_wallet()?;
            app.command("Watch-only descriptors", args(&["wallet", "descriptors", &w.id]), Vec::new(), true);
        }
        KeyCode::Char('D') => {
            let w = app.require_wallet()?;
            app.confirm(
                "Private descriptors",
                "These descriptors contain private keys: anyone who sees them can spend the funds.\nShow them?",
                move |app| {
                    app.wallet_command("Private descriptors", &w, args(&["wallet", "descriptors", &w.id, "--private"]), Vec::new(), true)
                },
            );
        }
        KeyCode::Char('k') => {
            let w = app.require_wallet()?;
            app.wallet_command("Check", &w, args(&["wallet", "check", &w.id]), Vec::new(), true);
        }
        KeyCode::Char('S') => {
            let w = app.require_wallet()?;
            app.confirm(
                "Show recovery words",
                "Make sure nobody can see your screen.\nShow the recovery words?",
                move |app| {
                    app.wallet_command(
                        "Recovery words",
                        &w,
                        args(&["wallet", "show-seed", &w.id]),
                        Vec::new(),
                        true,
                    )
                },
            );
        }
        KeyCode::Char('X') => {
            let w = app.require_wallet()?;
            app.confirm(
                "Export private keys",
                "This lists the private key of every address handed out.\nAnyone who sees them can spend the funds. Continue?",
                move |app| app.wallet_command("Private keys", &w, args(&["wallet", "export-keys", &w.id]), Vec::new(), true),
            );
        }
        KeyCode::Char('E') => {
            let w = app.require_wallet()?;
            app.push_form(Form::new(
                "Export a watching-only copy",
                vec![text("Save to").with(&home_dir()).help("A directory or a file name.")],
                move |app, v| {
                    let dest = shellexpand(v.str(0));
                    app.command(
                        "Export",
                        args(&["wallet", "export-watchonly", &w.id, &dest]),
                        Vec::new(),
                        false,
                    );
                    Ok(())
                },
            ));
        }
        KeyCode::Char('x') => {
            let w = app.require_wallet()?;
            app.confirm(
                "Remove wallet",
                format!("Remove wallet {} ({}) from Armory?\nThe file is kept (renamed). Make sure you have its recovery words.", w.label, w.id),
                move |app| app.command("Remove", args(&["wallet", "remove", &w.id, "--yes"]), Vec::new(), false),
            );
        }
        KeyCode::Char('L') => {
            let w = app.require_wallet()?;
            if !w.accounts.iter().any(|a| a.kind == AccountKind::Legacy135) {
                bail!("this wallet has no migrated Armory 0.93 accounts");
            }
            let targets = account_choices(&w, false);
            app.push_form(Form::new(
                "Sweep Armory 0.93 funds",
                vec![
                    choice("Into account", &targets.iter().map(String::as_str).collect::<Vec<_>>()),
                    text("Fee rate (sat/vB)").help("Empty: Bitcoin Core's estimate."),
                    text("Confirm within blocks").with("6"),
                    text("Unsigned PSBT file").help(
                        "Empty: sign and broadcast now. Otherwise write the PSBT for an offline signer.",
                    ),
                ],
                move |app, v| {
                    let to = account_index(v.str(0));
                    let fee = fee_args(v, 1, 2)?;
                    let id = w.id.clone();
                    prepare(app, "Sweep", unsigned_path(v, 3), move |ctx, core| {
                        ops::prepare_sweep_legacy(ctx, core, &id, None, to, &fee)
                    });
                    Ok(())
                },
            ));
        }
        _ => {}
    }
    Ok(())
}

/// Put text on the terminal's clipboard (OSC 52; supported by most terminals, incl. over SSH).
fn copy(app: &mut App, text: &str) {
    use bitcoin::base64::Engine as _;
    use std::io::Write;
    let b64 = bitcoin::base64::engine::general_purpose::STANDARD.encode(text);
    if !cfg!(test) {
        let mut out = std::io::stdout();
        let _ = write!(out, "\x1b]52;c;{b64}\x07");
        let _ = out.flush();
    }
    app.set_status(format!("Copied {text} (if the terminal allows clipboard access)"));
}

fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| ".".into())
}

/// "[i] name" labels of a wallet's accounts (legacy ones only when `legacy`).
fn account_choices(w: &ModernWallet, legacy: bool) -> Vec<String> {
    w.accounts
        .iter()
        .enumerate()
        .filter(|(_, a)| legacy || a.kind != AccountKind::Legacy135)
        .map(|(i, a)| format!("[{i}] {}", a.name))
        .collect()
}

fn account_index(label: &str) -> usize {
    label.trim_start_matches('[').split(']').next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn fee_args(v: &Values, rate: usize, target: usize) -> Result<FeeArgs> {
    let fee_rate = match v.opt(rate) {
        Some(r) => Some(r.parse::<f64>().map_err(|_| anyhow!("fee rate: a number of sat/vB"))?),
        None => None,
    };
    let target = match v.opt(target) {
        Some(t) => Some(t.parse::<u16>().map_err(|_| anyhow!("confirmation target: a number of blocks"))?),
        None => None,
    };
    Ok(FeeArgs { fee_rate, target: if fee_rate.is_some() { None } else { target } })
}

fn unsigned_path(v: &Values, i: usize) -> Option<PathBuf> {
    v.opt(i).map(|p| PathBuf::from(shellexpand(&p)))
}

/// Build a transaction on a worker thread; then confirm, ask the passphrase and broadcast
/// ([`prepared`]), or write it as an unsigned PSBT.
fn prepare(
    app: &mut App,
    label: &str,
    unsigned: Option<PathBuf>,
    f: impl FnOnce(&Context, &Core) -> Result<Prepared> + Send + 'static,
) {
    app.spawn(label, move |ctx, node| {
        let core = Core::new(&node.config(), ctx.network.bitcoin());
        let p = f(ctx, &core)?;
        if let Some(out) = unsigned {
            write_psbt(&out, &p.psbt)?;
            return Ok(Reply::Output {
                title: "Unsigned transaction".into(),
                text: Zeroizing::new(format!(
                    "{}\n\nUnsigned PSBT written to {}.\nSign it on the offline computer (Offline screen, or `armory tx sign`), then broadcast it here.",
                    summary_text(&p.summary),
                    out.display()
                )),
                show: true,
            });
        }
        Ok(Reply::Prepared(Box::new(p)))
    });
}

/// A checked transaction came back: show it, and sign and broadcast on confirmation.
pub fn prepared(app: &mut App, p: Prepared) {
    let summary = summary_text(&p.summary);
    app.screens.last_send = Some(summary.clone());
    app.confirm(
        "Review the transaction",
        format!("{summary}\n\nSign and broadcast this transaction?"),
        move |app| sign_and_send(app, p),
    );
}

/// Ask the passphrase, sign and broadcast; a wrong passphrase asks again.
pub fn sign_and_send(app: &mut App, p: Prepared) {
    let w = p.wallet.clone();
    app.with_passphrase(&w, move |app, pass| {
        app.spawn("Signing and broadcasting", move |ctx, node| {
            let u = match p.wallet.unlock(pass.as_ref().map(|x| x.as_bytes())) {
                Ok(u) => u,
                Err(ModernError::WrongPassphrase) => return Ok(Reply::Retry(Box::new(p))),
                Err(e) => return Err(e.into()),
            };
            let core = Core::new(&node.config(), ctx.network.bitcoin());
            let txid = ops::execute_unlocked(ctx, &core, p, &u)?;
            Ok(Reply::Output {
                title: "Sent".into(),
                text: Zeroizing::new(format!("Broadcast {txid}")),
                show: true,
            })
        });
    });
}

// ====================================================================== receive

/// (account, branch, index, address) of handed-out receive addresses of the selected account, newest first.
fn receive_addresses(app: &App) -> Vec<(u32, String)> {
    let Some(w) = app.wallet() else { return Vec::new() };
    let i = app.screens.account.min(w.accounts.len().saturating_sub(1));
    let Some(a) = w.accounts.get(i) else { return Vec::new() };
    (0..a.next_receive)
        .rev()
        .filter_map(|idx| w.address(i, 0, idx).ok().map(|ad| (idx, ad.to_string())))
        .collect()
}

fn draw_receive(f: &mut Frame, area: Rect, app: &App) {
    let Some(w) = app.wallet() else {
        return draw_text_screen(f, area, "Receive", "No wallet yet. Create one on the Wallets screen (2).");
    };
    let acct = app.screens.account;
    let a = &w.accounts[acct.min(w.accounts.len() - 1)];
    let addrs = receive_addresses(app);
    let [left, right] = Layout::horizontal([Constraint::Min(40), Constraint::Length(46)]).areas(area);
    let received = |addr: &str| -> i64 {
        app.wallet_data()
            .map(|d| {
                d.history
                    .iter()
                    .filter(|t| t.category == "receive" && t.address.as_deref() == Some(addr))
                    .map(|t| t.amount)
                    .sum()
            })
            .unwrap_or(0)
    };
    let rows: Vec<Row> = addrs
        .iter()
        .map(|(i, ad)| {
            let r = received(ad);
            Row::new(vec![
                Cell::from(i.to_string()),
                Cell::from(ad.clone()),
                Cell::from(if r > 0 { btc(r) } else { String::new() }),
                Cell::from(w.address_labels.get(ad).cloned().unwrap_or_default()),
            ])
        })
        .collect();
    let mut st = TableState::default().with_selected(Some(app.screens.addr_sel));
    f.render_stateful_widget(
        Table::new(
            rows,
            [Constraint::Length(5), Constraint::Length(64), Constraint::Length(14), Constraint::Min(10)],
        )
        .header(Row::new(vec!["#", "Address", "Received", "Label"]).bold())
        .row_highlight_style(hl())
        .block(panel(&format!("Account [{acct}] {}  (a: next account)", a.name))),
        left,
        &mut st,
    );
    let qr_body = match addrs.get(app.screens.addr_sel) {
        Some((_, ad)) => match qr_text(&format!("bitcoin:{ad}")) {
            Ok(q) => format!("{q}\n{ad}"),
            Err(_) => ad.clone(),
        },
        None => "No address handed out yet.\nPress n for a new receive address.".into(),
    };
    f.render_widget(Paragraph::new(qr_body).block(panel("Selected address")), right);
}

fn receive_key(app: &mut App, k: KeyEvent) -> Result<()> {
    let n = receive_addresses(app).len();
    if move_sel(&mut app.screens.addr_sel, n, &k) {
        return Ok(());
    }
    let w = app.require_wallet()?;
    let acct = app.screens.account;
    let selected = receive_addresses(app).get(app.screens.addr_sel).map(|x| x.1.clone());
    match k.code {
        KeyCode::Char('y') => {
            let ad = selected.ok_or_else(|| anyhow!("no address yet: press n"))?;
            copy(app, &ad);
        }
        KeyCode::Char('a') => {
            app.screens.account = (acct + 1) % w.accounts.len().max(1);
            app.screens.addr_sel = 0;
        }
        KeyCode::Char('n') => {
            app.screens.addr_sel = 0;
            app.command(
                "New address",
                args(&["address", "new", &w.id, "--account", &acct.to_string()]),
                Vec::new(),
                false,
            );
        }
        KeyCode::Enter => {
            let ad = selected.ok_or_else(|| anyhow!("no address yet: press n"))?;
            app.show("Address", format!("{}\n{ad}", qr_text(&format!("bitcoin:{ad}"))?));
        }
        KeyCode::Char('l') => {
            let ad = selected.ok_or_else(|| anyhow!("no address selected"))?;
            let cur = w.address_labels.get(&ad).cloned().unwrap_or_default();
            app.push_form(Form::new("Label address", vec![text("Label").with(&cur)], move |app, v| {
                app.command("Label", args(&["address", "label", &ad, v.str(0)]), Vec::new(), false);
                Ok(())
            }));
        }
        KeyCode::Char('u') => {
            let ad = selected.ok_or_else(|| anyhow!("no address yet: press n"))?;
            app.push_form(Form::new(
                "Payment request",
                vec![text("Amount (BTC)"), text("Label"), text("Message")],
                move |app, v| {
                    let mut a = args(&["uri", "create", &ad, "--qr"]);
                    for (flag, i) in [("--amount", 0), ("--label", 1), ("--message", 2)] {
                        if let Some(x) = v.opt(i) {
                            a.extend([flag.into(), x]);
                        }
                    }
                    app.command("Payment request", a, Vec::new(), true);
                    Ok(())
                },
            ));
        }
        _ => {}
    }
    Ok(())
}

// ====================================================================== send

fn draw_send(f: &mut Frame, area: Rect, app: &App) {
    let [top, bottom] = Layout::vertical([Constraint::Min(8), Constraint::Length(12)]).areas(area);
    let rows: Vec<Row> = app
        .screens
        .book
        .iter()
        .map(|e| {
            Row::new(vec![
                Cell::from(e.label.clone()),
                Cell::from(e.address.clone()),
                Cell::from(e.times_sent.to_string()),
            ])
        })
        .collect();
    let mut st = TableState::default().with_selected(Some(app.screens.book_sel));
    f.render_stateful_widget(
        Table::new(rows, [Constraint::Length(24), Constraint::Min(42), Constraint::Length(6)])
            .header(Row::new(vec!["Contact", "Address", "Paid"]).bold())
            .row_highlight_style(hl())
            .block(panel("Address book  (Enter: pay · b: add · d: delete)")),
        top,
        &mut st,
    );
    let mut t = String::new();
    if let Some(w) = app.wallet() {
        if let Some(b) = app.wallet_data().and_then(|d| d.balances.as_ref()) {
            t.push_str(&format!(
                "{}: {} BTC available, {} BTC pending\n",
                w.label,
                btc(b.confirmed),
                btc(b.pending)
            ));
        }
        if w.is_watching_only() {
            t.push_str(
                "Watching-only wallet: payments are written as unsigned PSBTs for the offline signer.\n",
            );
        }
    }
    match &app.screens.last_send {
        Some(s) => t.push_str(&format!("\nLast transaction:\n{s}")),
        None => t.push_str("\nPress n to make a payment. Bitcoin Core selects coins; Armory checks the transaction\nmatches what you asked, shows it, and signs only after you confirm."),
    }
    f.render_widget(Paragraph::new(t).block(panel("Send")).wrap(Wrap { trim: false }), bottom);
}

fn send_form(app: &mut App, to: &str, comment: &str, coins: Vec<String>) -> Result<()> {
    let w = app.require_wallet()?;
    let accounts = account_choices(&w, false);
    if accounts.is_empty() {
        bail!("this wallet has only legacy accounts: add a SegWit account (Wallets → A) or sweep them (L)");
    }
    let intro = if coins.is_empty() {
        "Coins of any account may be used; change goes to the chosen account.\nA recipient can be a lockbox: lockbox:ID=BTC.".to_string()
    } else {
        format!(
            "Coin control: spends exactly the {} marked coin(s); with \"send everything\", all of them.",
            coins.len()
        )
    };
    let unsigned_default =
        if w.is_watching_only() { format!("{}/unsigned.psbt", home_dir()) } else { String::new() };
    app.push_form(
        Form::new(
            &format!("Pay from {}", w.label),
            vec![
                multi("Recipients")
                    .with(to)
                    .help("One per line: ADDRESS=AMOUNT_BTC. With \"send everything\": just the address."),
                choice("From account", &accounts.iter().map(String::as_str).collect::<Vec<_>>()),
                toggle("Send everything")
                    .help("The whole confirmed balance of the account to one address, fee deducted."),
                text("Fee rate (sat/vB)").help("Empty: Bitcoin Core's estimate for the target below."),
                text("Confirm within blocks").with("6"),
                text("Comment").with(comment),
                text("Unsigned PSBT file")
                    .with(&unsigned_default)
                    .help("Empty: sign and broadcast now. Otherwise only write the PSBT (offline signing)."),
            ],
            move |app, v| {
                let to: Vec<String> =
                    v.str(0).lines().map(|l| l.trim().replace(' ', "")).filter(|l| !l.is_empty()).collect();
                let max = v.flag(2);
                let plain: Vec<String> = to.iter().filter(|t| !t.starts_with("lockbox:")).cloned().collect();
                if !plain.is_empty() {
                    ops::parse_recipients(&plain, max, w.network)?;
                }
                if to.is_empty() {
                    bail!("no recipient");
                }
                let spec = SendSpec {
                    wallet: w.id.clone(),
                    to,
                    max,
                    account: account_index(v.str(1)),
                    inputs: coins.clone(),
                    fee: fee_args(v, 3, 4)?,
                    comment: v.opt(5),
                };
                let coin_control = !spec.inputs.is_empty();
                prepare(app, "Building transaction", unsigned_path(v, 6), move |ctx, core| {
                    ops::prepare_send(ctx, core, &spec)
                });
                if coin_control {
                    app.screens.marked.clear();
                }
                Ok(())
            },
        )
        .intro(&intro),
    );
    Ok(())
}

fn send_key(app: &mut App, k: KeyEvent) -> Result<()> {
    let n = app.screens.book.len();
    if move_sel(&mut app.screens.book_sel, n, &k) {
        return Ok(());
    }
    match k.code {
        KeyCode::Char('n') => send_form(app, "", "", Vec::new())?,
        KeyCode::Enter => {
            let e = app.screens.book.get(app.screens.book_sel).cloned();
            match e {
                Some(e) => send_form(app, &format!("{}=", e.address), &e.label, Vec::new())?,
                None => send_form(app, "", "", Vec::new())?,
            }
        }
        KeyCode::Char('u') => {
            app.push_form(Form::new("Pay a bitcoin: link", vec![text("Link")], |app, v| {
                let p = PaymentUri::parse(v.str(0))?;
                let amount = p.amount_sat.map(|a| btc(a as i64)).unwrap_or_default();
                let comment = match (p.label, p.message) {
                    (Some(l), Some(m)) => format!("{l}: {m}"),
                    (l, m) => l.or(m).unwrap_or_default(),
                };
                send_form(app, &format!("{}={amount}", p.address), &comment, Vec::new())
            }))
        }
        KeyCode::Char('b') => {
            let cur = app.screens.book.get(app.screens.book_sel).cloned();
            app.push_form(Form::new(
                "Contact",
                vec![
                    text("Address").with(cur.as_ref().map(|c| c.address.as_str()).unwrap_or("")),
                    text("Name").with(cur.as_ref().map(|c| c.label.as_str()).unwrap_or("")),
                ],
                |app, v| {
                    let ad = v.opt(0).ok_or_else(|| anyhow!("address?"))?;
                    app.command(
                        "Address book",
                        args(&["addressbook", "add", &ad, v.str(1)]),
                        Vec::new(),
                        false,
                    );
                    Ok(())
                },
            ));
        }
        KeyCode::Char('d') => {
            let e = app.screens.book.get(app.screens.book_sel).cloned();
            let e = e.ok_or_else(|| anyhow!("the address book is empty"))?;
            {
                app.confirm(
                    "Delete contact",
                    format!("Remove {} ({}) from the address book?", e.label, e.address),
                    move |app| {
                        app.command(
                            "Address book",
                            args(&["addressbook", "remove", &e.address]),
                            Vec::new(),
                            false,
                        )
                    },
                );
            }
        }
        _ => {}
    }
    Ok(())
}

// ====================================================================== history

fn draw_history(f: &mut Frame, area: Rect, app: &App) {
    let Some(w) = app.wallet() else {
        return draw_text_screen(f, area, "History", "No wallet yet.");
    };
    let d = app.wallet_data();
    if let Some(e) = d.and_then(|d| d.error.as_ref()) {
        return draw_text_screen(
            f,
            area,
            "History",
            &format!("Bitcoin Core: {e}\n\nSync the wallet (Wallets → s) so Core watches it."),
        );
    }
    if app.screens.coins {
        let rows: Vec<Row> = d
            .map(|d| d.utxos.iter())
            .into_iter()
            .flatten()
            .map(|u| {
                let outpoint = format!("{}:{}", u.txid, u.vout);
                Row::new(vec![
                    Cell::from(if app.screens.marked.contains(&outpoint) { "●" } else { " " }),
                    Cell::from(btc(u.amount)),
                    Cell::from(u.confirmations.to_string()),
                    Cell::from(u.address.clone().unwrap_or_default()),
                    Cell::from(
                        u.address.as_ref().and_then(|a| w.address_labels.get(a)).cloned().unwrap_or_default(),
                    ),
                    Cell::from(outpoint),
                ])
            })
            .collect();
        let total: i64 = d.map(|d| d.utxos.iter().map(|u| u.amount).sum()).unwrap_or(0);
        let mut st = TableState::default().with_selected(Some(app.screens.coin_sel));
        f.render_stateful_widget(
            Table::new(
                rows,
                [
                    Constraint::Length(1),
                    Constraint::Length(14),
                    Constraint::Length(7),
                    Constraint::Length(44),
                    Constraint::Length(16),
                    Constraint::Min(20),
                ],
            )
            .header(Row::new(vec!["", "BTC", "Conf", "Address", "Label", "Outpoint"]).bold())
            .row_highlight_style(hl())
            .block(panel(&format!(
                "Coins of {} · {} BTC  (Space: mark · s: pay from the {} marked · v: transactions)",
                w.label,
                btc(total),
                app.screens.marked.len()
            ))),
            area,
            &mut st,
        );
        return;
    }
    let rows: Vec<Row> = d
        .map(|d| d.history.iter())
        .into_iter()
        .flatten()
        .map(|t| {
            let label = w
                .tx_comments
                .get(&t.txid)
                .cloned()
                .or_else(|| t.address.as_ref().and_then(|a| w.address_labels.get(a)).cloned())
                .unwrap_or_default();
            let style = if t.amount < 0 {
                Style::new().fg(Color::LightRed)
            } else {
                Style::new().fg(Color::LightGreen)
            };
            Row::new(vec![
                Cell::from(fmt_time(t.time)),
                Cell::from(if t.confirmations <= 0 { "unconf".into() } else { t.confirmations.to_string() }),
                Cell::from(btc(t.amount)).style(style),
                Cell::from(t.category.clone()),
                Cell::from(label),
                Cell::from(t.txid.clone()),
            ])
        })
        .collect();
    let mut st = TableState::default().with_selected(Some(app.screens.hist_sel));
    f.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Length(7),
                Constraint::Length(15),
                Constraint::Length(9),
                Constraint::Length(24),
                Constraint::Min(20),
            ],
        )
        .header(Row::new(vec!["Time (UTC)", "Conf", "BTC", "Type", "Comment / label", "Transaction"]).bold())
        .row_highlight_style(hl())
        .block(panel(&format!("Transactions of {}  (v: coins)", w.label))),
        area,
        &mut st,
    );
}

fn history_key(app: &mut App, k: KeyEvent) -> Result<()> {
    let (nh, nc) = app.wallet_data().map(|d| (d.history.len(), d.utxos.len())).unwrap_or((0, 0));
    if app.screens.coins {
        if move_sel(&mut app.screens.coin_sel, nc, &k) {
            return Ok(());
        }
    } else if move_sel(&mut app.screens.hist_sel, nh, &k) {
        return Ok(());
    }
    if k.code == KeyCode::Char('v') {
        app.screens.coins = !app.screens.coins;
        return Ok(());
    }
    let w = app.require_wallet()?;
    if app.screens.coins {
        let sel = app
            .wallet_data()
            .and_then(|d| d.utxos.get(app.screens.coin_sel))
            .map(|u| format!("{}:{}", u.txid, u.vout));
        match k.code {
            KeyCode::Char(' ') => {
                let c = sel.ok_or_else(|| anyhow!("no coins"))?;
                if !app.screens.marked.remove(&c) {
                    app.screens.marked.insert(c);
                }
                app.screens.coin_sel = (app.screens.coin_sel + 1).min(nc.saturating_sub(1));
                return Ok(());
            }
            KeyCode::Char('s') => {
                if app.screens.marked.is_empty() {
                    bail!("mark coins with Space first");
                }
                let coins: Vec<String> = app.screens.marked.iter().cloned().collect();
                return send_form(app, "", "", coins);
            }
            _ => {}
        }
        if k.code == KeyCode::Enter {
            if let Some(u) = app.wallet_data().and_then(|d| d.utxos.get(app.screens.coin_sel)).cloned() {
                app.show(
                    "Coin",
                    format!(
                        "Outpoint:      {}:{}\nAmount:        {} BTC\nConfirmations: {}\nAddress:       {}\nDescriptor:    {}",
                        u.txid,
                        u.vout,
                        btc(u.amount),
                        u.confirmations,
                        u.address.unwrap_or_default(),
                        u.descriptor.unwrap_or_default()
                    ),
                );
            }
        }
        return Ok(());
    }
    let t = app.wallet_data().and_then(|d| d.history.get(app.screens.hist_sel)).cloned();
    match k.code {
        KeyCode::Char('y') => {
            let t = t.ok_or_else(|| anyhow!("no transaction selected"))?;
            copy(app, &t.txid);
        }
        KeyCode::Enter => {
            let t = t.ok_or_else(|| anyhow!("no transaction selected"))?;
            let addr = t.address.clone().unwrap_or_default();
            app.show(
                "Transaction",
                format!(
                    "Transaction:   {}\nTime (UTC):    {}\nType:          {}\nAmount:        {} BTC\nFee:           {}\nConfirmations: {}\nAddress:       {} {}\nComment:       {}",
                    t.txid,
                    fmt_time(t.time),
                    t.category,
                    btc(t.amount),
                    t.fee.map(|f| format!("{} BTC", btc(f))).unwrap_or_else(|| "-".into()),
                    t.confirmations,
                    addr,
                    w.address_labels.get(&addr).map(|l| format!("({l})")).unwrap_or_default(),
                    w.tx_comments.get(&t.txid).cloned().unwrap_or_default()
                ),
            );
        }
        KeyCode::Char('c') => {
            let t = t.ok_or_else(|| anyhow!("no transaction selected"))?;
            let cur = w.tx_comments.get(&t.txid).cloned().unwrap_or_default();
            app.push_form(Form::new("Comment", vec![text("Comment").with(&cur)], move |app, v| {
                app.command("Comment", args(&["tx", "comment", &w.id, &t.txid, v.str(0)]), Vec::new(), false);
                Ok(())
            }));
        }
        KeyCode::Char('f') => {
            let t = t.ok_or_else(|| anyhow!("no transaction selected"))?;
            if t.confirmations > 0 {
                bail!("the transaction is already confirmed");
            }
            app.push_form(Form::new(
                "Raise the fee (RBF)",
                vec![text("New fee rate (sat/vB)")],
                move |app, v| {
                    let rate: f64 = v.str(0).parse().map_err(|_| anyhow!("a number of sat/vB"))?;
                    let (id, txid) = (w.id.clone(), t.txid.clone());
                    prepare(app, "Building replacement", None, move |ctx, core| {
                        ops::prepare_bump(ctx, core, &id, &txid, rate)
                    });
                    Ok(())
                },
            ));
        }
        KeyCode::Char('x') => {
            let t = t.ok_or_else(|| anyhow!("no transaction selected"))?;
            app.confirm(
                "Abandon transaction",
                format!("Forget unconfirmed transaction {}?\nIts coins become spendable again. It may still confirm if it was relayed.", t.txid),
                move |app| app.command("Abandon", args(&["tx", "abandon", &w.id, &t.txid]), Vec::new(), false),
            );
        }
        KeyCode::Char('e') => {
            app.push_form(Form::new(
                "Export history (CSV)",
                vec![text("File").with(&format!("{}/{}-history.csv", home_dir(), w.id))],
                move |app, v| {
                    let path = shellexpand(v.str(0));
                    app.command(
                        "Export",
                        args(&["history", &w.id, "--limit", "1000000", "--csv", &path]),
                        Vec::new(),
                        false,
                    );
                    Ok(())
                },
            ));
        }
        _ => {}
    }
    Ok(())
}

// ====================================================================== offline

fn draw_offline(f: &mut Frame, area: Rect, app: &App) {
    let body = match &app.screens.offline {
        Some(o) => format!(
            "File: {}{}\n\n{}",
            o.path.display(),
            if o.armory_format { "  (Armory 0.93 format)" } else { "" },
            o.summary
        ),
        None => OFFLINE_TEXT.into(),
    };
    f.render_widget(
        Paragraph::new(body).block(panel("Offline transaction")).wrap(Wrap { trim: false }),
        area,
    );
}

const OFFLINE_TEXT: &str = "Offline signing keeps the keys on a computer that never connects to the network.\n\n  1. Online computer (watching-only copy of the wallet): Send → n, fill in \"Unsigned PSBT file\".\n  2. Carry the file to the offline computer: here, o to open it, s to sign.\n  3. Carry the signed file back: o to open, b to broadcast.\n\nArmory 0.93 offline transactions (TXSIGCOLLECT) can be opened, signed and converted too.\nFor multisig lockboxes, each cosigner signs a copy; m combines them.";

fn load_offline(app: &mut App, path: PathBuf) {
    let id = app.wallet().map(|w| w.id.clone());
    app.spawn("Opening", move |ctx, _| {
        let net = ctx.network.bitcoin();
        let (psbt, armory_format) = crate::cli_tx::read_tx_file(&path, net)?;
        let scripts = match id {
            Some(id) => ops::own_scripts(&crate::cli_modern::open(ctx, &id)?.1),
            None => Vec::new(),
        };
        let summary = summary_text(&sign::summarize(&psbt, net, &|s| scripts.contains(s)));
        Ok(Reply::Offline(Box::new(OfflineTx { path, psbt, armory_format, summary })))
    });
}

fn offline_key(app: &mut App, k: KeyEvent) -> Result<()> {
    let loaded = app.screens.offline.as_ref().map(|o| o.path.clone());
    let need = || loaded.clone().ok_or_else(|| anyhow!("open a transaction first (o)"));
    match k.code {
        KeyCode::Char('r') => app.push_form(Form::new(
            "Broadcast a raw transaction",
            vec![multi("Signed transaction (hex)")],
            |app, v| {
                let hex: String = v.str(0).split_whitespace().collect();
                let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&hex)
                    .map_err(|e| anyhow!("not a raw transaction: {e}"))?;
                app.confirm(
                    "Broadcast",
                    format!(
                        "Broadcast transaction {} ({} inputs, {} outputs)?",
                        tx.compute_txid(),
                        tx.input.len(),
                        tx.output.len()
                    ),
                    move |app| {
                        app.command("Broadcast", args(&["tx", "broadcast", "--raw", &hex]), Vec::new(), true)
                    },
                );
                Ok(())
            },
        )),
        KeyCode::Char('o') => app.push_form(Form::new(
            "Open a transaction",
            vec![
                text("File").with(
                    &loaded
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| format!("{}/", home_dir())),
                ),
            ],
            |app, v| {
                load_offline(app, PathBuf::from(shellexpand(v.str(0))));
                Ok(())
            },
        )),
        KeyCode::Char('p') => app.push_form(Form::new(
            "Paste a transaction",
            vec![
                multi("PSBT (base64) or Armory block"),
                text("Save as").with(&format!("{}/pasted.psbt", home_dir())),
            ],
            |app, v| {
                let path = PathBuf::from(shellexpand(v.str(1)));
                if path.exists() {
                    bail!("{} already exists", path.display());
                }
                armory_wallet::store::atomic_write(&path, format!("{}\n", v.str(0)).as_bytes())?;
                load_offline(app, path);
                Ok(())
            },
        )),
        KeyCode::Char('s') => {
            let path = need()?;
            let w = app.require_wallet()?;
            app.push_form(Form::new(
                &format!("Sign with {}", w.label),
                vec![text("Write signed file to").with(&path.display().to_string())],
                move |app, v| {
                    let out = PathBuf::from(shellexpand(v.str(0)));
                    let base = app.base_args();
                    let (wid, src) = (w.id.clone(), path.clone());
                    app.with_passphrase(&w, move |app, pass| {
                        app.spawn("Signing", move |ctx, _| {
                            let mut a = base;
                            a.extend(args(&[
                                "tx",
                                "sign",
                                &src.display().to_string(),
                                "--wallet",
                                &wid,
                                "-o",
                                &out.display().to_string(),
                            ]));
                            let inputs =
                                pass.map(|p| vec![input("Passphrase for wallet", p)]).unwrap_or_default();
                            let (r, text) = crate::run_captured(&a, inputs);
                            r.map_err(|e| anyhow!("{}{e:#}", text.as_str()))?;
                            let net = ctx.network.bitcoin();
                            let (psbt, armory_format) = crate::cli_tx::read_tx_file(&out, net)?;
                            let scripts = ops::own_scripts(&crate::cli_modern::open(ctx, &wid)?.1);
                            let summary = format!(
                                "{}\n\n{}",
                                text.trim(),
                                summary_text(&sign::summarize(&psbt, net, &|s| scripts.contains(s)))
                            );
                            Ok(Reply::Offline(Box::new(OfflineTx {
                                path: out,
                                psbt,
                                armory_format,
                                summary,
                            })))
                        });
                    });
                    Ok(())
                },
            ));
        }
        KeyCode::Char('b') => {
            let path = need()?;
            let summary = app.screens.offline.as_ref().map(|o| o.summary.clone()).unwrap_or_default();
            app.confirm("Broadcast", format!("{summary}\n\nBroadcast this transaction?"), move |app| {
                app.command(
                    "Broadcast",
                    args(&["tx", "broadcast", &path.display().to_string()]),
                    Vec::new(),
                    true,
                )
            });
        }
        KeyCode::Char('c') => {
            let path = need()?;
            app.push_form(Form::new(
                "Convert",
                vec![choice("To", &["psbt", "armory"]), text("Output file")],
                move |app, v| {
                    let out = shellexpand(&v.opt(1).ok_or_else(|| anyhow!("output file?"))?);
                    app.command(
                        "Convert",
                        args(&["tx", "convert", &path.display().to_string(), "--to", v.str(0), "-o", &out]),
                        Vec::new(),
                        false,
                    );
                    Ok(())
                },
            ));
        }
        KeyCode::Char('m') => app.push_form(Form::new(
            "Combine signatures",
            vec![multi("Files (one per line)"), text("Output file")],
            |app, v| {
                let mut a = args(&["tx", "combine"]);
                a.extend(v.str(0).lines().map(|l| shellexpand(l.trim())).filter(|l| !l.is_empty()));
                let out = shellexpand(&v.opt(1).ok_or_else(|| anyhow!("output file?"))?);
                a.extend(["-o".into(), out.clone()]);
                app.command("Combine", a, Vec::new(), true);
                Ok(())
            },
        )),
        KeyCode::Char('v') => {
            need()?;
            app.push_form(Form::new("Save as PSBT", vec![text("File")], |app, v| {
                let out = PathBuf::from(shellexpand(&v.opt(0).ok_or_else(|| anyhow!("file?"))?));
                let o = app.screens.offline.as_ref().ok_or_else(|| anyhow!("nothing loaded"))?;
                write_psbt(&out, &o.psbt)?;
                app.set_status(format!("Wrote {}.", out.display()));
                Ok(())
            }));
        }
        _ => {}
    }
    Ok(())
}

// ====================================================================== lockboxes

fn draw_lockboxes(f: &mut Frame, area: Rect, app: &App) {
    let [left, right] = Layout::horizontal([Constraint::Length(34), Constraint::Min(30)]).areas(area);
    let items: Vec<ListItem> = app
        .lockboxes
        .iter()
        .map(|(_, l)| ListItem::new(format!("{}  {}-of-{}  {}", l.id, l.m, l.keys.len(), l.name)))
        .collect();
    let mut st = ListState::default().with_selected(Some(app.screens.lb_sel));
    f.render_stateful_widget(List::new(items).block(panel("Lockboxes")).highlight_style(hl()), left, &mut st);
    let body = match app.lockboxes.get(app.screens.lb_sel) {
        Some((p, l)) => {
            let mut s = format!(
                "{} ({})\n{}-of-{} {:?}\nFile: {}\nNext deposit index: {}\n\nKeys:\n",
                l.name,
                l.id,
                l.m,
                l.keys.len(),
                l.kind,
                p.display(),
                l.next_receive
            );
            for (i, k) in l.keys.iter().enumerate() {
                s.push_str(&format!("  {}. {k} {}\n", i + 1, l.key_comments.get(i).cloned().unwrap_or_default()));
            }
            s.push_str("\nDescriptors:\n");
            for d in l.descriptors() {
                s.push_str(&format!("  {d}\n"));
            }
            s
        }
        None => "No lockboxes.\n\nA lockbox is an M-of-N multisig address shared by several people or devices.\n  k  export the selected wallet's cosigner key, send it to the other participants\n  n  create the lockbox once you have everyone's key\n  i  import a lockbox file (or Armory 0.93 multisigs.txt / LOCKBOX blocks)".into(),
    };
    f.render_widget(Paragraph::new(body).block(panel("Details")).wrap(Wrap { trim: false }), right);
}

fn lockbox_key(app: &mut App, k: KeyEvent) -> Result<()> {
    let n = app.lockboxes.len();
    if move_sel(&mut app.screens.lb_sel, n, &k) {
        return Ok(());
    }
    let sel = app.lockboxes.get(app.screens.lb_sel).map(|(_, l)| l.id.clone());
    let need = || sel.clone().ok_or_else(|| anyhow!("no lockbox selected"));
    match k.code {
        KeyCode::Char('k') => {
            let w = app.require_wallet()?;
            app.push_form(Form::new(
                "Export cosigner key",
                vec![text("Account").with("0")],
                move |app, v| {
                    let a = args(&["lockbox", "export-key", &w.id, "--account", v.str(0)]);
                    app.wallet_command("Cosigner key", &w, a, Vec::new(), true);
                    Ok(())
                },
            ));
        }
        KeyCode::Char('n') => {
            let wid = app.wallet().map(|w| w.label.clone()).unwrap_or_default();
            app.push_form(Form::new(
                "Create a lockbox",
                vec![
                    text("Name"),
                    text("Signatures required (M)").with("2"),
                    multi("Cosigner keys")
                        .help("One [fingerprint/48h/...]xpub per line, from `k` on each cosigner."),
                    toggle(&format!("Include {wid}"))
                        .with("true")
                        .help("Add the selected wallet as one of the cosigners."),
                ],
                |app, v| {
                    let name = v.opt(0).ok_or_else(|| anyhow!("name?"))?;
                    let mut a = args(&["lockbox", "create", "--name", &name, "-m", v.str(1)]);
                    for key in v.str(2).lines().map(str::trim).filter(|l| !l.is_empty()) {
                        a.extend(["--key".into(), key.into()]);
                    }
                    if v.flag(3) {
                        let w = app.require_wallet()?;
                        a.extend(["--with-wallet".into(), w.id.clone()]);
                        app.wallet_command("Lockbox", &w, a, Vec::new(), true);
                    } else {
                        app.command("Lockbox", a, Vec::new(), true);
                    }
                    Ok(())
                },
            ));
        }
        KeyCode::Char('i') => app.push_form(Form::new(
            "Import lockboxes",
            vec![
                text("File")
                    .help("A .lockbox file, Armory 0.93 multisigs.txt, or a text file with LOCKBOX blocks."),
            ],
            |app, v| {
                app.command("Import", args(&["lockbox", "import", &shellexpand(v.str(0))]), Vec::new(), true);
                Ok(())
            },
        )),
        KeyCode::Char('e') => {
            let id = need()?;
            app.push_form(Form::new(
                "Export lockbox",
                vec![text("Save to").with(&home_dir())],
                move |app, v| {
                    app.command(
                        "Export",
                        args(&["lockbox", "export", &id, &shellexpand(v.str(0))]),
                        Vec::new(),
                        false,
                    );
                    Ok(())
                },
            ));
        }
        KeyCode::Char('s') => {
            let id = need()?;
            app.push_form(Form::new("Sync lockbox", vec![toggle("Skip the rescan")], move |app, v| {
                let mut a = args(&["lockbox", "sync", &id]);
                if v.flag(0) {
                    a.push("--no-rescan".into());
                }
                app.command("Sync lockbox", a, Vec::new(), false);
                Ok(())
            }));
        }
        KeyCode::Char('a') => {
            let id = need()?;
            let mut a = app.base_args();
            a.extend(args(&["lockbox", "address", &id]));
            app.spawn("Lockbox address", move |_, _| {
                let (r, text) = crate::run_captured(&a, Vec::new());
                r?;
                let addr = text.trim().lines().last().unwrap_or("").to_string();
                let q = qr_text(&format!("bitcoin:{addr}")).unwrap_or_default();
                Ok(Reply::Output {
                    title: "Lockbox deposit address".into(),
                    text: Zeroizing::new(format!("{q}\n{}", text.trim())),
                    show: true,
                })
            });
        }
        KeyCode::Char('b') => {
            let id = need()?;
            app.command("Lockbox balance", args(&["lockbox", "balance", &id]), Vec::new(), true);
        }
        KeyCode::Char('u') => {
            let id = need()?;
            app.command("Lockbox coins", args(&["lockbox", "utxos", &id]), Vec::new(), true);
        }
        KeyCode::Char('p') => {
            let id = need()?;
            app.push_form(
                Form::new(
                    "Spend from lockbox",
                    vec![
                        multi("Recipients").help("One per line: ADDRESS=AMOUNT_BTC"),
                        text("Fee rate (sat/vB)"),
                        text("Confirm within blocks").with("6"),
                        text("PSBT file").with(&format!("{}/{id}-spend.psbt", home_dir())),
                    ],
                    move |app, v| {
                        let mut a = args(&["lockbox", "spend", &id]);
                        for t in v.str(0).lines().map(|l| l.trim().replace(' ', "")).filter(|l| !l.is_empty()) {
                            a.extend(["--to".into(), t]);
                        }
                        let fee = fee_args(v, 1, 2)?;
                        if let Some(r) = fee.fee_rate {
                            a.extend(["--fee-rate".into(), r.to_string()]);
                        } else if let Some(t) = fee.target {
                            a.extend(["--target".into(), t.to_string()]);
                        }
                        let out = shellexpand(&v.opt(3).ok_or_else(|| anyhow!("PSBT file?"))?);
                        a.extend(["-o".into(), out]);
                        app.command("Lockbox spend", a, Vec::new(), true);
                        Ok(())
                    },
                )
                .intro("Writes a PSBT. Each cosigner signs it (Offline → o, s); combine the copies (m) and broadcast (b)."),
            );
        }
        _ => {}
    }
    Ok(())
}

// ====================================================================== backup

const BACKUP_TEXT: &str = "Your recovery words are the backup of a modern wallet: with them (and the BIP39\npassphrase, if you set one) the wallet can be restored in Armory or any BIP39 wallet.\n\n  p  Paper backup of the selected wallet: recovery words plus Easy16 lines for migrated\n     Armory 0.93 accounts. SecurePrint masks the sheet with a code you write separately.\n  f  Fragmented backup: M of N fragments are needed to restore; fewer reveal nothing.\n  t  Test a paper backup against the selected wallet   T  test fragments\n  R  Restore from a paper backup (modern, or Armory 0.93 with \"Armory 0.93 sheet\")\n  F  Restore from fragments (modern or Armory 0.93, detected)\n\nWatching-only copies and descriptors are on the Wallets screen (E, d).";

fn backup_key(app: &mut App, k: KeyEvent) -> Result<()> {
    match k.code {
        KeyCode::Char('d') => {
            let w = app.require_wallet()?;
            app.push_form(Form::new(
                "Digital backup (copy of the wallet file)",
                vec![text("Save to").with(&home_dir()).help("A directory or file, e.g. on a USB stick.")],
                move |app, v| {
                    app.command(
                        "Digital backup",
                        args(&["backup", "file", &w.id, &shellexpand(v.str(0))]),
                        Vec::new(),
                        false,
                    );
                    Ok(())
                },
            ));
        }
        KeyCode::Char('p') => {
            let w = app.require_wallet()?;
            app.push_form(Form::new(
                "Paper backup",
                vec![toggle("SecurePrint"), text("Save to file").help("Empty: show it on screen.")],
                move |app, v| {
                    let mut a = args(&["backup", "paper", &w.id]);
                    if v.flag(0) {
                        a.push("--secureprint".into());
                    }
                    if let Some(o) = v.opt(1) {
                        a.extend(["-o".into(), shellexpand(&o)]);
                    }
                    app.wallet_command("Paper backup", &w, a, Vec::new(), true);
                    Ok(())
                },
            ));
        }
        KeyCode::Char('f') => {
            let w = app.require_wallet()?;
            app.push_form(Form::new(
                "Fragmented backup",
                vec![
                    text("Needed (M)").with("2"),
                    text("Total (N)").with("3"),
                    toggle("SecurePrint"),
                    text("Save to directory").help("Empty: show them on screen."),
                ],
                move |app, v| {
                    let mut a = args(&["backup", "fragments", &w.id, "-m", v.str(0), "-n", v.str(1)]);
                    if v.flag(2) {
                        a.push("--secureprint".into());
                    }
                    if let Some(o) = v.opt(3) {
                        a.extend(["--output-dir".into(), shellexpand(&o)]);
                    }
                    app.wallet_command("Fragments", &w, a, Vec::new(), true);
                    Ok(())
                },
            ));
        }
        KeyCode::Char('t') => restore_form(app, false, true)?,
        KeyCode::Char('T') => restore_form(app, true, true)?,
        KeyCode::Char('R') => restore_form(app, false, false)?,
        KeyCode::Char('F') => restore_form(app, true, false)?,
        _ => {}
    }
    Ok(())
}

/// Restore (or test) a paper backup or fragments.
fn restore_form(app: &mut App, fragments: bool, test: bool) -> Result<()> {
    let w = if test { Some(app.require_wallet()?) } else { None };
    let mut fields = Vec::new();
    if !fragments {
        fields.push(toggle("Armory 0.93 sheet"));
        fields.push(
            text("Line group")
                .help("Sheets with several groups of lines: 1 = seed, then the Armory 0.93 accounts."),
        );
    }
    fields.push(multi(if fragments { "Fragments" } else { "Backup lines" }).help(if fragments {
        "Paste the ID: and F1:..F4: lines of each fragment."
    } else {
        "The Easy16 lines (or recovery words section) exactly as on the sheet; typos are corrected when possible."
    }));
    fields.push(secret("SecurePrint code").help("Only for sheets printed with SecurePrint."));
    let base = fields.len();
    if !test {
        fields.push(text("Name").with("Restored"));
        fields.push(secret("BIP39 passphrase"));
        fields.push(secret("Passphrase"));
        fields.push(secret("Repeat passphrase"));
        fields.push(toggle("Store unencrypted"));
    }
    let title = match (fragments, test) {
        (false, true) => "Test a paper backup",
        (true, true) => "Test fragments",
        (false, false) => "Restore from a paper backup",
        (true, false) => "Restore from fragments",
    };
    app.push_form(Form::new(title, fields, move |app, v| {
        let mut a = args(&["restore", if fragments { "fragments" } else { "paper" }]);
        let mut i = 0;
        if !fragments {
            if v.flag(0) {
                a.push("--legacy".into());
            }
            if let Some(b) = v.opt(1) {
                a.extend(["--block".into(), b]);
            }
            i = 2;
        }
        let what = if fragments { "fragments" } else { "backup lines" };
        if v.str(i).is_empty() {
            bail!("paste the {what}");
        }
        let mut inputs: Inputs = vec![input(what, Zeroizing::new(v.raw(i).to_string()))];
        if !v.raw(i + 1).is_empty() {
            if !fragments {
                a.push("--secureprint".into());
            }
            inputs.push(input("SecurePrint code", v.secret(i + 1)));
        }
        match &w {
            Some(w) => {
                a.extend(["--test".into(), w.id.clone()]);
                app.wallet_command("Backup test", w, a, inputs, true);
            }
            None => {
                a.extend(["--label".into(), v.str(base).to_string()]);
                if !v.raw(base + 1).is_empty() {
                    a.push("--bip39-passphrase".into());
                    inputs.push(input("BIP39 passphrase", v.secret(base + 1)));
                }
                match new_pass(v, base + 2, base + 3, base + 4)? {
                    Some(p) => inputs.push(input("New passphrase", p)),
                    None => a.push("--no-encrypt".into()),
                }
                app.command("Restore", a, inputs, true);
            }
        }
        Ok(())
    }));
    Ok(())
}

// ====================================================================== tools

fn draw_tools(f: &mut Frame, area: Rect, _app: &App) {
    draw_text_screen(
        f,
        area,
        "Tools",
        "  s  Sign a message with one of your addresses (BIP322, Bitcoin-Qt, Armory clearsign)\n  v  Verify a signed message\n  b  Verify an Armory \"BITCOIN SIGNED MESSAGE\" block\n  k  Sweep a private key (paper wallet, old Armory key) into the selected wallet\n  i  Show addresses and WIF for a private key\n  d  Decode a raw transaction\n  u  Decode a bitcoin: payment link\n  l  List Armory 0.93 wallet files\n\n  :  Run any armory command, e.g. `legacy wallet show ID` or `legacy address keys ADDRESS`.\n     The output appears here; prompts are answered from the dialog.",
    );
}

fn tools_key(app: &mut App, k: KeyEvent) -> Result<()> {
    match k.code {
        KeyCode::Char('s') => {
            let w = app.require_wallet()?;
            let addr = receive_addresses(app).first().map(|x| x.1.clone()).unwrap_or_default();
            app.push_form(Form::new(
                "Sign a message",
                vec![
                    text("Address").with(&addr).help("An address of the selected wallet."),
                    multi("Message"),
                    choice("Format", &["auto", "bip322", "bip137", "clearsign"]),
                ],
                move |app, v| {
                    let ad = v.opt(0).ok_or_else(|| anyhow!("address?"))?;
                    let a = args(&[
                        "message",
                        "sign",
                        &ad,
                        "--message",
                        v.raw(1).trim_end_matches('\n'),
                        "--format",
                        v.str(2),
                    ]);
                    app.wallet_command("Signature", &w, a, Vec::new(), true);
                    Ok(())
                },
            ));
        }
        KeyCode::Char('v') => app.push_form(Form::new(
            "Verify a message",
            vec![text("Address"), text("Signature"), multi("Message")],
            |app, v| {
                let a = args(&[
                    "message",
                    "verify",
                    "--address",
                    v.str(0),
                    "--signature",
                    v.str(1),
                    "--message",
                    v.raw(2).trim_end_matches('\n'),
                ]);
                app.command("Verification", a, Vec::new(), true);
                Ok(())
            },
        )),
        KeyCode::Char('b') => app.push_form(Form::new(
            "Verify an Armory signed block",
            vec![multi("Block"), text("Expected signer").help("Optional.")],
            |app, v| {
                let mut a = args(&["message", "verify", "--block", "-"]);
                if let Some(s) = v.opt(1) {
                    a.extend(["--address".into(), s]);
                }
                app.command(
                    "Verification",
                    a,
                    vec![input("signed block", Zeroizing::new(v.raw(0).to_string()))],
                    true,
                );
                Ok(())
            },
        )),
        KeyCode::Char('k') => {
            let w = app.require_wallet()?;
            app.push_form(Form::new(
                &format!("Sweep a private key into {}", w.label),
                vec![
                    secret("Private key").help("WIF, hex or mini key."),
                    text("Fee rate (sat/vB)"),
                    text("Confirm within blocks").with("6"),
                ],
                move |app, v| {
                    let key = v.secret(0);
                    if key.trim().is_empty() {
                        bail!("type the private key");
                    }
                    let fee = fee_args(v, 1, 2)?;
                    let mut a = args(&["sweep", &w.id, "--yes"]);
                    if let Some(r) = fee.fee_rate {
                        a.extend(["--fee-rate".into(), r.to_string()]);
                    } else if let Some(t) = fee.target {
                        a.extend(["--target".into(), t.to_string()]);
                    }
                    let label = w.label.clone();
                    app.confirm(
                        "Sweep",
                        format!("Move every coin this key controls into {label}?"),
                        move |app| app.command("Sweep", a, vec![input("Private key", key)], true),
                    );
                    Ok(())
                },
            ));
        }
        KeyCode::Char('i') => {
            app.push_form(Form::new("Key information", vec![secret("Private key")], |app, v| {
                app.command(
                    "Key",
                    args(&["tools", "key-info"]),
                    vec![input("Private key", v.secret(0))],
                    true,
                );
                Ok(())
            }))
        }
        KeyCode::Char('d') => app.push_form(Form::new(
            "Decode a transaction",
            vec![multi("Raw transaction (hex)")],
            |app, v| {
                let hex: String = v.str(0).split_whitespace().collect();
                app.command("Transaction", args(&["tools", "decode-tx", &hex]), Vec::new(), true);
                Ok(())
            },
        )),
        KeyCode::Char('u') => {
            app.push_form(Form::new("Decode a payment link", vec![text("Link")], |app, v| {
                app.command("Payment link", args(&["uri", "parse", v.str(0)]), Vec::new(), true);
                Ok(())
            }))
        }
        KeyCode::Char('l') => {
            app.command("Armory 0.93 wallets", args(&["legacy", "wallet", "list"]), Vec::new(), true)
        }
        _ => {}
    }
    Ok(())
}

/// Split a command line into words (double or single quotes group words).
pub fn split_words(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;
    for c in s.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                any = true;
            }
            (None, c) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if quote.is_some() {
        bail!("unbalanced quote");
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

/// `:`: run any armory command.
pub fn command_palette(app: &mut App) {
    app.push_form(
        Form::new(
            "Run a command",
            vec![
                text("armory"),
                secret("Wallet passphrase").help("Answers \"Passphrase for wallet …\" and \"Passphrase of legacy wallet …\"."),
                secret("New passphrase"),
                multi("Input").help("Answers other prompts: recovery words, private keys, backup text, codes."),
            ],
            |app, v| {
                let words = split_words(v.str(0))?;
                if words.is_empty() {
                    bail!("type a command, e.g. `legacy wallet list` or `--help`");
                }
                if matches!(words[0].as_str(), "tui" | "completions" | "manpage") {
                    bail!("`{}` is for the shell", words[0]);
                }
                let mut inputs: Inputs = Vec::new();
                if !v.raw(1).is_empty() {
                    inputs.push(input("Passphrase", v.secret(1)));
                }
                if !v.raw(2).is_empty() {
                    inputs.push(input("New passphrase", v.secret(2)));
                }
                if !v.raw(3).is_empty() {
                    let t = Zeroizing::new(v.raw(3).trim_end_matches('\n').to_string());
                    for key in ["Recovery phrase", "Private key", "backup lines", "fragments", "signed block", "SecurePrint code", "BIP39 passphrase"] {
                        inputs.push(input(key, t.clone()));
                    }
                }
                let title = format!("armory {}", v.str(0));
                app.command(&title, words, inputs, true);
                Ok(())
            },
        )
        .intro("Any armory command (without global options; the TUI adds network, data directory and node).\nExamples: `wallet list`, `legacy wallet show 2bShZzjK`, `tx show ~/x.psbt`, `--help`."),
    );
}

// ====================================================================== settings

fn draw_settings(f: &mut Frame, area: Rect, app: &App) {
    let cfg = crate::config::path(app.datadir.as_deref());
    let node = &app.node;
    let or = |o: Option<String>, d: &str| o.unwrap_or_else(|| d.to_string());
    let body = format!(
        "Network:            {}\nData directory:     {}\nSettings file:      {}\n\nBitcoin Core connection\n  RPC address:      {}\n  Cookie file:      {}\n  RPC user:         {}\n  Core data dir:    {}\n\n{}\n\n  n  switch network     c  change the connection     t  test it     a  about",
        net_name(app.ctx.network),
        app.ctx.data_root.display(),
        cfg.map(|p| p.display().to_string()).unwrap_or_else(|| "-".into()),
        or(node.rpc_addr.clone(), "127.0.0.1 (default port of the network)"),
        or(node.rpc_cookie.as_ref().map(|p| p.display().to_string()), "found in the Core data directory"),
        or(node.rpc_user.clone(), "- (cookie authentication)"),
        or(
            node.bitcoin_datadir.as_ref().map(|p| p.display().to_string()),
            "default (~/.bitcoin, ~/Library/Application Support/Bitcoin)"
        ),
        match &app.node_status {
            Some(Ok(s)) => format!(
                "Connected: Bitcoin Core {} on {}, {} blocks.",
                s.subversion.trim_matches('/'),
                s.chain,
                s.blocks
            ),
            Some(Err(e)) => format!("Not connected: {e}"),
            None => "Connecting…".into(),
        }
    );
    f.render_widget(Paragraph::new(body).block(panel("Settings")).wrap(Wrap { trim: false }), area);
}

fn settings_key(app: &mut App, k: KeyEvent) -> Result<()> {
    match k.code {
        KeyCode::Char('n') => {
            let cur = net_name(app.ctx.network);
            app.push_form(Form::new(
                "Network",
                vec![
                    choice("Network", &["mainnet", "testnet4", "testnet3", "signet", "regtest"]).with(cur),
                    toggle("Make it the default"),
                ],
                |app, v| {
                    let n = match v.str(0) {
                        "mainnet" => Network::Mainnet,
                        "testnet4" => Network::Testnet4,
                        "testnet3" => Network::Testnet3,
                        "signet" => Network::Signet,
                        _ => Network::Regtest,
                    };
                    app.set_network(n)?;
                    if v.flag(1) {
                        app.command(
                            "Settings",
                            args(&["config", "set", "network", v.str(0)]),
                            Vec::new(),
                            false,
                        );
                    }
                    app.set_status(format!("Network: {}", v.str(0)));
                    Ok(())
                },
            ));
        }
        KeyCode::Char('c') => {
            let n = app.node.clone();
            let s = |o: Option<String>| o.unwrap_or_default();
            let p = |o: Option<PathBuf>| o.map(|x| x.display().to_string()).unwrap_or_default();
            app.push_form(
                Form::new(
                    "Bitcoin Core connection",
                    vec![
                        text("RPC address")
                            .with(&s(n.rpc_addr.clone()))
                            .help("host:port; empty for 127.0.0.1 and the network's default port."),
                        text("Cookie file").with(&p(n.rpc_cookie.clone())),
                        text("RPC user")
                            .with(&s(n.rpc_user.clone()))
                            .help("Only with rpcauth; cookie authentication is preferred."),
                        secret("RPC password").with(&s(n.rpc_password.clone())),
                        text("Core data directory").with(&p(n.bitcoin_datadir.clone())),
                        toggle("Save as defaults")
                            .help("Write to the settings file (the password is never saved)."),
                    ],
                    |app, v| {
                        app.node.rpc_addr = v.opt(0);
                        app.node.rpc_cookie = v.opt(1).map(|x| PathBuf::from(shellexpand(&x)));
                        app.node.rpc_user = v.opt(2);
                        app.node.rpc_password = Some(v.raw(3).to_string()).filter(|x| !x.is_empty());
                        app.node.bitcoin_datadir = v.opt(4).map(|x| PathBuf::from(shellexpand(&x)));
                        if v.flag(5) {
                            let datadir = app.datadir.clone();
                            let pairs: Vec<(&str, Option<String>)> = vec![
                                ("rpc-addr", v.opt(0)),
                                ("rpc-cookie", v.opt(1).map(|x| shellexpand(&x))),
                                ("rpc-user", v.opt(2)),
                                ("bitcoin-datadir", v.opt(4).map(|x| shellexpand(&x))),
                            ];
                            let pairs: Vec<(String, Option<String>)> =
                                pairs.into_iter().map(|(k, x)| (k.to_string(), x)).collect();
                            app.spawn("Saving settings", move |_, _| {
                                for (k, val) in pairs {
                                    let mut a: Vec<String> = Vec::new();
                                    if let Some(d) = &datadir {
                                        a.extend(["--datadir".into(), d.display().to_string()]);
                                    }
                                    match val {
                                        Some(x) => a.extend(args(&["config", "set", &k, &x])),
                                        None => a.extend(args(&["config", "unset", &k])),
                                    }
                                    crate::run_captured(&a, Vec::new()).0?;
                                }
                                Ok(Reply::Status("Settings saved.".into()))
                            });
                        }
                        app.refresh();
                        Ok(())
                    },
                )
                .intro("Armory talks only to your own Bitcoin Core node (29.0 or newer recommended)."),
            );
        }
        KeyCode::Char('t') => {
            app.node_status = None;
            app.refresh();
        }
        KeyCode::Char('a') => app.command("About", args(&["about"]), Vec::new(), true),
        _ => {}
    }
    Ok(())
}

fn draw_text_screen(f: &mut Frame, area: Rect, title: &str, body: &str) {
    f.render_widget(Paragraph::new(body.to_string()).block(panel(title)).wrap(Wrap { trim: false }), area);
}
