//! Terminal UI tests: every screen renders, and actions run the CLI commands through the dialogs.

use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use super::Setup;
use super::app::App;
use super::screens::{self, Tab};
use super::widgets::Modal;
use crate::cli_node::NodeArgs;
use crate::context::{Context, Network};

fn key(app: &mut App, c: KeyCode) {
    app.on_key(KeyEvent::new(c, KeyModifiers::NONE));
}

fn typ(app: &mut App, s: &str) {
    for c in s.chars() {
        key(app, KeyCode::Char(c));
    }
}

fn submit(app: &mut App) {
    app.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
}

fn wait(app: &mut App) {
    let start = Instant::now();
    loop {
        app.poll();
        if app.busy.is_empty() && app.node_status.is_some() {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(60), "job did not finish");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn render(app: &App) -> String {
    let mut t = Terminal::new(TestBackend::new(140, 45)).unwrap();
    t.draw(|f| screens::draw(f, app)).unwrap();
    let buf = t.backend().buffer().clone();
    let mut s = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            s.push_str(buf[(x, y)].symbol());
        }
        s.push('\n');
    }
    s
}

fn top_view(app: &App) -> String {
    match app.modals.last() {
        Some(Modal::View(v)) => v.body.to_string(),
        Some(Modal::Form(f)) => format!("form: {} {:?}", f.title, f.error),
        Some(Modal::Confirm(c)) => format!("confirm: {}", c.body),
        None => format!("no dialog; status: {:?}", app.status),
    }
}

/// A regtest data directory with one encrypted wallet ("pw"), created through the CLI path.
fn setup() -> (tempfile::TempDir, App) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display().to_string();
    let (r, out) = crate::run_captured(
        &[
            "--network",
            "regtest",
            "--datadir",
            &d,
            "wallet",
            "create",
            "--label",
            "Savings",
            "--words",
            "12",
            "--kdf-memory-mib",
            "1",
            "--kdf-iterations",
            "1",
        ]
        .map(String::from),
        vec![("New passphrase".into(), Zeroizing::new("pw".into()))],
    );
    r.unwrap();
    assert!(out.contains("Recovery phrase"), "{}", out.as_str());
    let ctx = Context::new(Network::Regtest, Some(dir.path().into()), None).unwrap();
    // A node that is not there: every Core call fails fast.
    let node = NodeArgs {
        rpc_addr: Some("127.0.0.1:1".into()),
        rpc_cookie: Some(dir.path().join("no-cookie")),
        ..Default::default()
    };
    let app = App::new(Setup { ctx, node, datadir: Some(dir.path().into()), passphrase_file: None });
    (dir, app)
}

#[test]
fn every_screen_renders_without_a_node() {
    let (_d, mut app) = setup();
    wait(&mut app);
    assert_eq!(app.wallets.len(), 1);
    for c in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'] {
        key(&mut app, KeyCode::Char(c));
        let s = render(&app);
        assert!(s.contains("Savings"), "screen {c}:\n{s}");
        key(&mut app, KeyCode::Char('?'));
        assert!(render(&app).contains("Everywhere"));
        key(&mut app, KeyCode::Esc);
    }
    key(&mut app, KeyCode::Char('1'));
    assert!(render(&app).contains("Not connected to Bitcoin Core"));
    // History screen in coin mode, and a too-small terminal, do not panic either.
    key(&mut app, KeyCode::Char('5'));
    key(&mut app, KeyCode::Char('v'));
    render(&app);
    let mut t = Terminal::new(TestBackend::new(30, 8)).unwrap();
    t.draw(|f| screens::draw(f, &app)).unwrap();
}

#[test]
fn dialogs_run_the_cli_commands() {
    let (_d, mut app) = setup();
    wait(&mut app);
    let id = app.wallet().unwrap().id.clone();

    // Rename (no passphrase needed).
    key(&mut app, KeyCode::Char('2'));
    key(&mut app, KeyCode::Char('e'));
    for _ in 0..10 {
        key(&mut app, KeyCode::Backspace);
    }
    typ(&mut app, "Cold storage");
    submit(&mut app);
    wait(&mut app);
    assert_eq!(app.wallet().unwrap().label, "Cold storage", "{}", top_view(&app));

    // A form refuses bad input and stays open.
    key(&mut app, KeyCode::Char('e'));
    for _ in 0..20 {
        key(&mut app, KeyCode::Backspace);
    }
    submit(&mut app);
    assert!(top_view(&app).contains("cannot be empty"), "{}", top_view(&app));
    key(&mut app, KeyCode::Esc);
    assert!(app.modals.is_empty());

    // New receive address.
    key(&mut app, KeyCode::Char('3'));
    key(&mut app, KeyCode::Char('n'));
    wait(&mut app);
    assert_eq!(app.wallet().unwrap().accounts[0].next_receive, 1);
    assert!(render(&app).contains("bcrt1q"));
    key(&mut app, KeyCode::Enter);
    assert!(top_view(&app).contains("bcrt1q"));
    key(&mut app, KeyCode::Esc);

    // Paper backup: the wallet passphrase is asked, then the sheet is shown.
    key(&mut app, KeyCode::Char('8'));
    key(&mut app, KeyCode::Char('p'));
    submit(&mut app);
    assert!(top_view(&app).contains("Passphrase for"), "{}", top_view(&app));
    typ(&mut app, "wrong");
    submit(&mut app);
    wait(&mut app);
    assert!(top_view(&app).to_lowercase().contains("passphrase"), "{}", top_view(&app));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('p'));
    submit(&mut app);
    typ(&mut app, "pw");
    submit(&mut app);
    wait(&mut app);
    let sheet = top_view(&app);
    assert!(sheet.contains(&id), "{sheet}");
    key(&mut app, KeyCode::Esc);

    // Command palette: any CLI command.
    app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
    typ(&mut app, "wallet show ");
    typ(&mut app, &id);
    submit(&mut app);
    wait(&mut app);
    assert!(top_view(&app).contains("Cold storage"), "{}", top_view(&app));
    key(&mut app, KeyCode::Esc);

    // Sending needs Bitcoin Core: the error is shown, nothing crashes.
    key(&mut app, KeyCode::Char('4'));
    key(&mut app, KeyCode::Char('n'));
    typ(&mut app, "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080=0.1");
    submit(&mut app);
    wait(&mut app);
    assert!(matches!(app.modals.last(), Some(Modal::View(v)) if v.error), "{}", top_view(&app));
}

#[test]
fn helpers() {
    assert_eq!(
        screens::split_words(r#"wallet rename X --label "My wallet" ''"#).unwrap(),
        ["wallet", "rename", "X", "--label", "My wallet", ""]
    );
    assert!(screens::split_words("a \"b").is_err());
    assert_eq!(screens::fmt_time(1_231_006_505), "2009-01-03 18:15");
    assert_eq!(screens::btc(-12_345), "-0.00012345");
    assert_eq!(Tab::from_digit('0'), Some(Tab::Settings));
}
