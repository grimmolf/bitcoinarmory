//! Application state, background jobs and global key handling.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use armory_node::core::{Balances, Core, NodeStatus, TxEntry, Utxo};
use armory_wallet::lockbox::Lockbox;
use armory_wallet::modern::ModernWallet;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use super::Setup;
use super::screens::Tab;
use super::widgets::{Confirm, Form, Modal, Values, Viewer, secret};
use crate::cli_node::NodeArgs;
use crate::context::{Context, Network};
use crate::io::Inputs;
use crate::ops::Prepared;

/// What a background job hands back to the UI thread.
pub enum Reply {
    /// Output of a command; shown in a viewer when `show`, else as the status line.
    Output {
        title: String,
        text: Zeroizing<String>,
        show: bool,
    },
    Node(std::result::Result<NodeStatus, String>),
    Data(String, WalletData),
    Prepared(Box<Prepared>),
    /// Wrong passphrase for a prepared transaction: ask again.
    Retry(Box<Prepared>),
    Offline(Box<super::screens::OfflineTx>),
    Status(String),
}

type Job = Box<dyn FnOnce(&Context, &NodeArgs) -> Result<Reply> + Send>;

struct Done {
    label: String,
    result: Result<Reply>,
}

/// What Bitcoin Core knows about one wallet.
#[derive(Default, Clone)]
pub struct WalletData {
    pub balances: Option<Balances>,
    pub history: Vec<TxEntry>,
    pub utxos: Vec<Utxo>,
    pub error: Option<String>,
}

pub struct App {
    pub ctx: Context,
    pub node: NodeArgs,
    pub datadir: Option<PathBuf>,
    pub passphrase_file: Option<PathBuf>,
    pub tab: Tab,
    pub wallets: Vec<(PathBuf, ModernWallet)>,
    pub wsel: usize,
    pub lockboxes: Vec<(PathBuf, Lockbox)>,
    pub node_status: Option<std::result::Result<NodeStatus, String>>,
    pub data: HashMap<String, WalletData>,
    pub modals: Vec<Modal>,
    pub status: (String, bool),
    pub busy: Vec<String>,
    /// Jobs not yet finished, quiet ones included.
    pub inflight: usize,
    pub tick: usize,
    pub quit: bool,
    pub screens: super::screens::State,
    last_refresh: Instant,
    tx: Sender<Done>,
    rx: Receiver<Done>,
}

impl App {
    pub fn new(s: Setup) -> Self {
        let (tx, rx) = channel();
        let mut app = App {
            ctx: s.ctx,
            node: s.node,
            datadir: s.datadir,
            passphrase_file: s.passphrase_file,
            tab: Tab::Overview,
            wallets: Vec::new(),
            wsel: 0,
            lockboxes: Vec::new(),
            node_status: None,
            data: HashMap::new(),
            modals: Vec::new(),
            status: (String::new(), false),
            busy: Vec::new(),
            inflight: 0,
            tick: 0,
            quit: false,
            screens: Default::default(),
            last_refresh: Instant::now(),
            tx,
            rx,
        };
        app.reload();
        app.refresh();
        app
    }

    // ------------------------------------------------------------------ data

    /// Re-read wallet and lockbox files (fast, offline).
    pub fn reload(&mut self) {
        let selected = self.wallet().map(|w| w.id.clone());
        let ctx = self.ctx.clone();
        let (r, warnings) = crate::io::capture(Vec::new(), || {
            Ok::<_, anyhow::Error>((crate::cli_modern::wallets(&ctx)?, crate::cli_lockbox::lockboxes(&ctx)?))
        });
        match r {
            Ok((mut w, l)) => {
                w.sort_by_key(|a| a.1.label.to_lowercase());
                self.wallets = w;
                self.lockboxes = l;
            }
            Err(e) => self.set_error(format!("{e:#}")),
        }
        if !warnings.trim().is_empty() {
            self.set_error(warnings.trim().replace('\n', "; "));
        }
        if let Some(id) = selected {
            if let Some(i) = self.wallets.iter().position(|(_, w)| w.id == id) {
                self.wsel = i;
            }
        }
        self.wsel = self.wsel.min(self.wallets.len().saturating_sub(1));
        super::screens::clamp(self);
    }

    /// Ask Core for the node status and every wallet's balance, history and coins.
    pub fn refresh(&mut self) {
        self.last_refresh = Instant::now();
        let net = self.ctx.network.bitcoin();
        self.spawn_quiet("node status", move |_, node| {
            Ok(Reply::Node(Core::new(&node.config(), net).status().map_err(|e| e.to_string())))
        });
        let ids: Vec<String> = self.wallets.iter().map(|(_, w)| w.id.clone()).collect();
        for id in ids {
            self.spawn_quiet("wallet data", move |_, node| {
                let core = Core::new(&node.config(), net);
                let mut d = WalletData::default();
                match core.balances(&id) {
                    Ok(b) => {
                        d.balances = Some(b);
                        d.history = core.history(&id, 500, 0).unwrap_or_default();
                        d.utxos = core.utxos(&id, 0).unwrap_or_default();
                    }
                    Err(e) => d.error = Some(e.to_string()),
                }
                Ok(Reply::Data(id, d))
            });
        }
    }

    pub fn wallet(&self) -> Option<&ModernWallet> {
        self.wallets.get(self.wsel).map(|(_, w)| w)
    }

    pub fn require_wallet(&self) -> Result<ModernWallet> {
        self.wallet()
            .cloned()
            .ok_or_else(|| anyhow!("no wallet yet: create or restore one on the Wallets screen"))
    }

    pub fn wallet_data(&self) -> Option<&WalletData> {
        self.wallet().and_then(|w| self.data.get(&w.id))
    }

    pub fn set_status(&mut self, s: impl Into<String>) {
        self.status = (s.into(), false);
    }

    pub fn set_error(&mut self, s: impl Into<String>) {
        self.status = (s.into(), true);
    }

    // ------------------------------------------------------------------ jobs

    fn spawn_job(&mut self, label: &str, quiet: bool, job: Job) {
        if !quiet {
            self.busy.push(label.to_string());
        }
        self.inflight += 1;
        let (ctx, node, tx) = (self.ctx.clone(), self.node.clone(), self.tx.clone());
        let label = if quiet { String::new() } else { label.to_string() };
        std::thread::spawn(move || {
            // Anything a job prints would scribble over the screen: capture (and drop) it.
            let (result, _) = crate::io::capture(Vec::new(), || job(&ctx, &node));
            let _ = tx.send(Done { label, result });
        });
    }

    /// Run `f` on a worker thread (with a busy indicator).
    pub fn spawn(
        &mut self,
        label: &str,
        f: impl FnOnce(&Context, &NodeArgs) -> Result<Reply> + Send + 'static,
    ) {
        self.spawn_job(label, false, Box::new(f));
    }

    fn spawn_quiet(
        &mut self,
        label: &str,
        f: impl FnOnce(&Context, &NodeArgs) -> Result<Reply> + Send + 'static,
    ) {
        self.spawn_job(label, true, Box::new(f));
    }

    /// Global options for commands run on the user's behalf.
    pub fn base_args(&self) -> Vec<String> {
        let mut a = vec!["--network".to_string(), net_name(self.ctx.network).to_string()];
        let mut opt = |flag: &str, v: Option<String>| {
            if let Some(v) = v {
                a.push(flag.into());
                a.push(v);
            }
        };
        opt("--datadir", self.datadir.as_ref().map(|p| p.display().to_string()));
        opt("--passphrase-file", self.passphrase_file.as_ref().map(|p| p.display().to_string()));
        opt("--rpc-addr", self.node.rpc_addr.clone());
        opt("--rpc-cookie", self.node.rpc_cookie.as_ref().map(|p| p.display().to_string()));
        opt("--rpc-user", self.node.rpc_user.clone());
        opt("--rpc-password", self.node.rpc_password.clone());
        opt("--bitcoin-datadir", self.node.bitcoin_datadir.as_ref().map(|p| p.display().to_string()));
        a
    }

    /// Run an `armory` command line exactly as the CLI would, answering its prompts from `inputs`.
    /// `show`: present the output in a viewer (else on the status line).
    pub fn command(&mut self, title: &str, args: Vec<String>, inputs: Inputs, show: bool) {
        let mut full = self.base_args();
        full.extend(args);
        let title = title.to_string();
        self.spawn(&title.clone(), move |_, _| {
            let (r, text) = crate::run_captured(&full, inputs);
            match r {
                Ok(()) => Ok(Reply::Output { title, text, show }),
                Err(e) => {
                    let mut msg = text.trim_end().to_string();
                    if !msg.is_empty() {
                        msg.push_str("\n\n");
                    }
                    Err(anyhow!("{msg}error: {e:#}"))
                }
            }
        });
    }

    /// `command` with the selected wallet's passphrase (asked first when the wallet is encrypted).
    pub fn wallet_command(
        &mut self,
        title: &str,
        w: &ModernWallet,
        args: Vec<String>,
        mut inputs: Inputs,
        show: bool,
    ) {
        let title = title.to_string();
        self.with_passphrase(w, move |app, pass| {
            if let Some(p) = pass {
                inputs.push(("Passphrase for wallet".into(), p));
            }
            app.command(&title, args, inputs, show);
        });
    }

    /// Ask for a wallet's passphrase if it has one, then continue.
    pub fn with_passphrase(
        &mut self,
        w: &ModernWallet,
        then: impl FnOnce(&mut App, Option<Zeroizing<String>>) + 'static,
    ) {
        if !w.is_encrypted() {
            then(self, None);
            return;
        }
        if self.passphrase_file.is_some() {
            match self.ctx.passphrase("") {
                Ok(p) => then(self, Some(p)),
                Err(e) => self.show_error(format!("{e:#}")),
            }
            return;
        }
        let mut then = Some(then);
        self.push_form(Form::new(
            &format!("Passphrase for {} ({})", w.label, w.id),
            vec![secret("Passphrase")],
            move |app, v: &Values| {
                if let Some(t) = then.take() {
                    t(app, Some(v.secret(0)));
                }
                Ok(())
            },
        ));
    }

    pub fn push_form(&mut self, f: Form) {
        self.modals.push(Modal::Form(f));
    }

    pub fn show(&mut self, title: &str, body: impl Into<String>) {
        self.modals.push(Modal::View(Viewer {
            title: title.into(),
            body: Zeroizing::new(body.into()),
            scroll: 0,
            error: false,
        }));
    }

    pub fn show_error(&mut self, body: impl Into<String>) {
        let body = body.into();
        self.set_error(body.lines().last().unwrap_or("").to_string());
        self.modals.push(Modal::View(Viewer {
            title: "Error".into(),
            body: Zeroizing::new(body),
            scroll: 0,
            error: true,
        }));
    }

    pub fn confirm(&mut self, title: &str, body: impl Into<String>, on_yes: impl FnOnce(&mut App) + 'static) {
        self.modals.push(Modal::Confirm(Confirm {
            title: title.into(),
            body: body.into(),
            on_yes: Some(Box::new(on_yes)),
        }));
    }

    /// Switch network (wallets are per network).
    pub fn set_network(&mut self, n: Network) -> Result<()> {
        self.ctx = Context::new(n, self.datadir.clone(), self.passphrase_file.clone())?;
        self.data.clear();
        self.node_status = None;
        self.wsel = 0;
        self.reload();
        self.refresh();
        Ok(())
    }

    // ------------------------------------------------------------------ events

    /// Collect finished jobs and refresh periodically.
    pub fn poll(&mut self) {
        while let Ok(d) = self.rx.try_recv() {
            self.inflight = self.inflight.saturating_sub(1);
            if !d.label.is_empty() {
                if let Some(i) = self.busy.iter().position(|b| *b == d.label) {
                    self.busy.remove(i);
                }
            }
            let user_job = !d.label.is_empty();
            match d.result {
                Ok(Reply::Node(s)) => self.node_status = Some(s),
                Ok(Reply::Data(id, data)) => {
                    // A transaction we had not seen: say so (the old GUI's "surprise tx" popup).
                    if let Some(old) = self.data.get(&id).filter(|o| o.balances.is_some()) {
                        let new: Vec<&TxEntry> = data
                            .history
                            .iter()
                            .filter(|t| !old.history.iter().any(|o| o.txid == t.txid))
                            .collect();
                        if let Some(t) = new.first() {
                            let label =
                                self.wallets.iter().find(|(_, w)| w.id == id).map(|(_, w)| w.label.clone());
                            self.set_status(format!(
                                "New transaction in {}: {} BTC ({}){}",
                                label.unwrap_or(id.clone()),
                                super::screens::btc(t.amount),
                                t.category,
                                if new.len() > 1 {
                                    format!(" and {} more", new.len() - 1)
                                } else {
                                    String::new()
                                }
                            ));
                        }
                    }
                    self.data.insert(id, data);
                    super::screens::clamp(self);
                }
                Ok(Reply::Output { title, text, show }) => {
                    if show {
                        self.show(&title, text.trim_end().to_string());
                        self.set_status(format!("{title}: done"));
                    } else {
                        let last = text.trim().lines().last().unwrap_or("done").to_string();
                        self.set_status(last);
                    }
                }
                Ok(Reply::Prepared(p)) => super::screens::prepared(self, *p),
                Ok(Reply::Retry(p)) => {
                    self.set_error("Wrong passphrase; try again (Esc cancels).");
                    super::screens::sign_and_send(self, *p);
                }
                Ok(Reply::Offline(o)) => {
                    self.screens.offline = Some(*o);
                    self.tab = Tab::Offline;
                }
                Ok(Reply::Status(s)) => self.set_status(s),
                Err(e) => self.show_error(format!("{e:#}")),
            }
            if user_job {
                self.reload();
                self.refresh();
            }
        }
        if self.last_refresh.elapsed() > Duration::from_secs(30) && self.inflight == 0 {
            self.refresh();
        }
        self.tick = self.tick.wrapping_add(1);
    }

    pub fn on_paste(&mut self, s: &str) {
        if let Some(Modal::Form(f)) = self.modals.last_mut() {
            f.paste(s);
        }
    }

    pub fn on_key(&mut self, k: KeyEvent) {
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            if self.modals.is_empty() {
                self.quit = true;
            } else {
                self.modals.pop();
            }
            return;
        }
        if let Some(m) = self.modals.last_mut() {
            match m {
                Modal::View(v) => {
                    if v.key(k) {
                        self.modals.pop();
                    }
                }
                Modal::Confirm(_) => match k.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        if let Some(Modal::Confirm(mut c)) = self.modals.pop() {
                            if let Some(f) = c.on_yes.take() {
                                f(self);
                            }
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Char('q') => {
                        self.modals.pop();
                    }
                    _ => {}
                },
                Modal::Form(f) => {
                    if k.code == KeyCode::Esc {
                        self.modals.pop();
                        return;
                    }
                    if f.key(k) {
                        if let Some(Modal::Form(mut f)) = self.modals.pop() {
                            let values = f.values();
                            let depth = self.modals.len();
                            if let Err(e) = (f.on_submit)(self, &values) {
                                f.error = Some(format!("{e:#}"));
                                self.modals.insert(depth, Modal::Form(f));
                            }
                        }
                    }
                }
            }
            return;
        }
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Tab => self.tab = self.tab.next(),
            KeyCode::BackTab => self.tab = self.tab.prev(),
            KeyCode::Char(c @ '0'..='9') => {
                if let Some(t) = Tab::from_digit(c) {
                    self.tab = t;
                }
            }
            KeyCode::Char(']') | KeyCode::Char('w') => {
                if !self.wallets.is_empty() {
                    self.wsel = (self.wsel + 1) % self.wallets.len();
                    super::screens::clamp(self);
                }
            }
            KeyCode::Char('[') | KeyCode::Char('W') => {
                if !self.wallets.is_empty() {
                    self.wsel = (self.wsel + self.wallets.len() - 1) % self.wallets.len();
                    super::screens::clamp(self);
                }
            }
            KeyCode::Char('r') | KeyCode::F(5) => {
                self.reload();
                self.refresh();
                self.set_status("Refreshing…");
            }
            KeyCode::Char('?') | KeyCode::F(1) => self.show("Help", super::screens::help(self.tab)),
            KeyCode::Char(':') => super::screens::command_palette(self),
            _ => {
                if let Err(e) = super::screens::on_key(self, k) {
                    self.show_error(format!("{e:#}"));
                }
            }
        }
    }
}

pub fn net_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet3 => "testnet3",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}
