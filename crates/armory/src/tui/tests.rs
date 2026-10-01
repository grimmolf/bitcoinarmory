//! Terminal UI tests: every screen renders, and actions run the CLI commands through the dialogs.

use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use super::Setup;
use super::app::{App, GLOBAL_KEYS};
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
        if app.inflight == 0 {
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
            "--taproot",
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

/// Every key the help and footer advertise does something on its screen.
#[test]
fn every_advertised_key_does_something() {
    let (_d, mut app) = setup();
    wait(&mut app);
    // An address to act on.
    key(&mut app, KeyCode::Char('3'));
    key(&mut app, KeyCode::Char('n'));
    wait(&mut app);
    let screens: [(char, &str); 10] = [
        ('1', "s\n"),
        ('2', "cRImsepAdDkSXExL"),
        ('3', "na\nlyu"),
        ('4', "nu\nbd"),
        ('5', "v\nycfxe"),
        ('6', "ophsbcmv"),
        ('7', "nkiesabup"),
        ('8', "pdftTRF"),
        ('9', "svbkidul"),
        ('0', "ncta"),
    ];
    for (_, keys) in screens {
        for k in keys.chars() {
            assert!(!GLOBAL_KEYS.contains(&k), "{k:?} is a global key: the screen can never receive it");
        }
    }
    for (tab, keys) in screens {
        for k in keys.chars() {
            key(&mut app, KeyCode::Char(tab));
            let snap = |a: &App| {
                (a.modals.len(), a.inflight, a.status.clone(), a.tab, a.screens.coins, a.screens.account)
            };
            let before = snap(&app);
            key(&mut app, if k == '\n' { KeyCode::Enter } else { KeyCode::Char(k) });
            assert_ne!(snap(&app), before, "screen {tab}: key {k:?} did nothing");
            app.modals.clear();
            wait(&mut app);
            app.modals.clear();
            app.screens.coins = false;
        }
    }
    // Coins view: Space marks, s pays from the marked coins (both report "no coins" here).
    key(&mut app, KeyCode::Char('5'));
    key(&mut app, KeyCode::Char('v'));
    for k in [' ', 's'] {
        let before = app.modals.len();
        key(&mut app, KeyCode::Char(k));
        assert_eq!(app.modals.len(), before + 1, "coins: key {k:?}");
        app.modals.clear();
    }
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

/// The TUI's own payment flow against a real `bitcoind -regtest` (skipped unless `ARMORY_BITCOIND`
/// names one, as in tests/regtest.rs): sync, receive, then send through the dialogs (form, review,
/// passphrase).
#[test]
fn regtest_send_through_the_dialogs() {
    use armory_node::{Auth, RpcClient};
    use serde_json::json;
    let Some(bitcoind) = std::env::var_os("ARMORY_BITCOIND") else {
        eprintln!("skipping: set ARMORY_BITCOIND to a bitcoind binary to run this test");
        return;
    };
    let free_port = || std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let core_dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut child = std::process::Command::new(bitcoind)
        .arg("-regtest")
        .arg(format!("-datadir={}", core_dir.path().display()))
        .arg(format!("-rpcport={port}"))
        .arg(format!("-port={}", free_port()))
        .args(["-server", "-listen=0", "-fallbackfee=0.0002", "-printtoconsole=0"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("start bitcoind");
    let rpc =
        RpcClient::new(format!("127.0.0.1:{port}"), Auth::Cookie(core_dir.path().join("regtest/.cookie")));
    let deadline = Instant::now() + Duration::from_secs(60);
    while rpc.call(None, "getblockchaininfo", json!([])).is_err() {
        assert!(Instant::now() < deadline, "bitcoind did not start");
        std::thread::sleep(Duration::from_millis(250));
    }
    let run = || {
        rpc.call(None, "createwallet", json!(["miner"])).unwrap();
        let miner =
            rpc.call(Some("miner"), "getnewaddress", json!([])).unwrap().as_str().unwrap().to_string();
        rpc.call(None, "generatetoaddress", json!([101, miner])).unwrap();

        let (_d, mut app) = setup();
        wait(&mut app); // the initial refresh against the placeholder node
        app.node.rpc_addr = Some(format!("127.0.0.1:{port}"));
        app.node.rpc_cookie = None;
        app.node.bitcoin_datadir = Some(core_dir.path().into());
        app.node_status = None;
        app.refresh();
        wait(&mut app);
        assert!(
            matches!(app.node_status, Some(Ok(_))),
            "{:?}",
            app.node_status.as_ref().map(|s| s.as_ref().err())
        );

        // Sync (Overview → s → default rescan).
        key(&mut app, KeyCode::Char('s'));
        submit(&mut app);
        wait(&mut app);
        assert!(app.modals.is_empty(), "{}", top_view(&app));

        // Receive 1 BTC.
        key(&mut app, KeyCode::Char('3'));
        key(&mut app, KeyCode::Char('n'));
        wait(&mut app);
        let addr = app.wallet().unwrap().address(0, 0, 0).unwrap().to_string();
        rpc.call(Some("miner"), "sendtoaddress", json!([addr, 1.0])).unwrap();
        rpc.call(None, "generatetoaddress", json!([1, miner])).unwrap();
        key(&mut app, KeyCode::Char('r'));
        wait(&mut app);
        assert_eq!(
            app.wallet_data().and_then(|d| d.balances.clone()).map(|b| b.confirmed),
            Some(100_000_000)
        );

        // Pay 0.3 BTC at 2 sat/vB.
        key(&mut app, KeyCode::Char('4'));
        key(&mut app, KeyCode::Char('n'));
        typ(&mut app, &format!("{miner}=0.3"));
        for _ in 0..3 {
            key(&mut app, KeyCode::Tab);
        }
        typ(&mut app, "2");
        submit(&mut app);
        wait(&mut app);
        assert!(
            top_view(&app).starts_with("confirm:") && top_view(&app).contains(" 0.3 BTC"),
            "{}",
            top_view(&app)
        );
        key(&mut app, KeyCode::Char('y'));
        assert!(top_view(&app).contains("Passphrase for"), "{}", top_view(&app));
        typ(&mut app, "pw");
        submit(&mut app);
        wait(&mut app);
        let sent = top_view(&app);
        assert!(sent.starts_with("Broadcast "), "{sent}");
        let txid = sent.trim_start_matches("Broadcast ").trim().to_string();
        let mempool = rpc.call(None, "getrawmempool", json!([])).unwrap();
        assert!(mempool.as_array().unwrap().iter().any(|t| t.as_str() == Some(txid.as_str())), "{mempool}");
        key(&mut app, KeyCode::Esc);

        // History shows it, with the address book entry recorded.
        key(&mut app, KeyCode::Char('5'));
        assert!(render(&app).contains(&txid[..20]));
        assert!(app.screens.book.iter().any(|e| e.address == miner));
    };
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
    let _ = rpc.call(None, "stop", json!([]));
    std::thread::sleep(Duration::from_millis(500));
    let _ = child.kill();
    let _ = child.wait();
    if let Err(e) = r {
        std::panic::resume_unwind(e);
    }
}

#[test]
fn a_panicking_job_is_reported_not_fatal() {
    let (_d, mut app) = setup();
    wait(&mut app);
    app.spawn("boom", |_, _| panic!("kaboom"));
    wait(&mut app);
    assert!(app.busy.is_empty());
    assert!(top_view(&app).contains("internal error (please report): kaboom"), "{}", top_view(&app));
}

#[test]
fn a_second_tui_on_one_datadir_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let first = super::lock(dir.path()).unwrap();
    let err = super::lock(dir.path()).unwrap_err().to_string();
    assert!(err.contains("Another Armory TUI is already running"), "{err}");
    drop(first);
    super::lock(dir.path()).unwrap();
}
