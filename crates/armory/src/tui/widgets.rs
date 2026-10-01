//! Dialogs: forms, confirmations and a scrollable text viewer.

use anyhow::Result;
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use zeroize::Zeroizing;

use super::app::App;

#[derive(Clone)]
pub enum Kind {
    Text,
    /// Hidden input (passphrases, keys, recovery words).
    Secret,
    /// Several lines; Enter inserts a line break.
    Multi,
    Toggle,
    Choice(Vec<String>),
}

pub struct Field {
    pub label: String,
    pub kind: Kind,
    pub value: Zeroizing<String>,
    pub choice: usize,
    pub help: String,
}

impl Field {
    fn new(label: &str, kind: Kind) -> Self {
        Field {
            label: label.into(),
            kind,
            value: Zeroizing::new(String::new()),
            choice: 0,
            help: String::new(),
        }
    }
}

pub fn text(label: &str) -> Field {
    Field::new(label, Kind::Text)
}
pub fn secret(label: &str) -> Field {
    Field::new(label, Kind::Secret)
}
pub fn multi(label: &str) -> Field {
    Field::new(label, Kind::Multi)
}
pub fn toggle(label: &str) -> Field {
    Field::new(label, Kind::Toggle)
}
pub fn choice(label: &str, options: &[&str]) -> Field {
    Field::new(label, Kind::Choice(options.iter().map(|s| s.to_string()).collect()))
}

impl Field {
    pub fn with(mut self, value: &str) -> Self {
        match &self.kind {
            Kind::Toggle => self.value = Zeroizing::new(if value == "true" { "true" } else { "" }.into()),
            Kind::Choice(o) => self.choice = o.iter().position(|x| x == value).unwrap_or(0),
            _ => self.value = Zeroizing::new(value.into()),
        }
        self
    }
    pub fn help(mut self, h: &str) -> Self {
        self.help = h.into();
        self
    }
}

/// Submitted values, by field position.
pub struct Values(Vec<Zeroizing<String>>);

impl Values {
    pub fn str(&self, i: usize) -> &str {
        self.0[i].trim()
    }
    pub fn raw(&self, i: usize) -> &str {
        &self.0[i]
    }
    pub fn secret(&self, i: usize) -> Zeroizing<String> {
        self.0[i].clone()
    }
    pub fn flag(&self, i: usize) -> bool {
        &*self.0[i] == "true"
    }
    /// Non-empty trimmed value.
    pub fn opt(&self, i: usize) -> Option<String> {
        Some(self.str(i).to_string()).filter(|s| !s.is_empty())
    }
}

pub type OnSubmit = Box<dyn FnMut(&mut App, &Values) -> Result<()>>;

pub struct Form {
    pub title: String,
    pub intro: String,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub error: Option<String>,
    pub on_submit: OnSubmit,
}

impl Form {
    pub fn new(
        title: &str,
        fields: Vec<Field>,
        on_submit: impl FnMut(&mut App, &Values) -> Result<()> + 'static,
    ) -> Self {
        Form {
            title: title.into(),
            intro: String::new(),
            fields,
            focus: 0,
            error: None,
            on_submit: Box::new(on_submit),
        }
    }
    pub fn intro(mut self, t: &str) -> Self {
        self.intro = t.into();
        self
    }

    pub fn values(&self) -> Values {
        Values(
            self.fields
                .iter()
                .map(|f| match &f.kind {
                    Kind::Choice(o) => Zeroizing::new(o.get(f.choice).cloned().unwrap_or_default()),
                    _ => f.value.clone(),
                })
                .collect(),
        )
    }

    /// Handle a key; true means "submit".
    pub fn key(&mut self, k: KeyEvent) -> bool {
        let n = self.fields.len();
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let f = &mut self.fields[self.focus];
        match k.code {
            KeyCode::Char('s') if ctrl => return true,
            KeyCode::F(10) => return true,
            KeyCode::Char('u') if ctrl => f.value = Zeroizing::new(String::new()),
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % n,
            KeyCode::BackTab | KeyCode::Up => self.focus = (self.focus + n - 1) % n,
            KeyCode::Enter => match f.kind {
                Kind::Multi => f.value.push('\n'),
                _ if self.focus + 1 == n => return true,
                _ => self.focus += 1,
            },
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                if matches!(f.kind, Kind::Toggle | Kind::Choice(_)) =>
            {
                match &f.kind {
                    Kind::Toggle => {
                        let on = &*f.value == "true";
                        f.value = Zeroizing::new(if on { String::new() } else { "true".into() });
                    }
                    Kind::Choice(o) => {
                        f.choice = if k.code == KeyCode::Left {
                            (f.choice + o.len() - 1) % o.len()
                        } else {
                            (f.choice + 1) % o.len()
                        }
                    }
                    _ => {}
                }
            }
            KeyCode::Backspace => {
                f.value.pop();
            }
            KeyCode::Char(c) if !matches!(f.kind, Kind::Toggle | Kind::Choice(_)) => f.value.push(c),
            _ => {}
        }
        false
    }

    pub fn paste(&mut self, s: &str) {
        let f = &mut self.fields[self.focus];
        match f.kind {
            Kind::Multi => f.value.push_str(&s.replace("\r\n", "\n")),
            Kind::Text | Kind::Secret => f.value.push_str(s.lines().collect::<Vec<_>>().join(" ").trim()),
            _ => {}
        }
    }

    fn height(&self) -> u16 {
        let fields: u16 = self.fields.iter().map(|f| if matches!(f.kind, Kind::Multi) { 6 } else { 1 }).sum();
        let intro = if self.intro.is_empty() { 0 } else { self.intro.lines().count() as u16 + 1 };
        fields + intro + 5
    }

    pub fn draw(&self, f: &mut Frame, area: Rect) {
        let area = centered(area, 86, self.height());
        f.render_widget(Clear, area);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .title(format!(" {} ", self.title))
            .title_bottom(
                Line::from(" Enter next/submit · Tab move · Space/←→ change · Ctrl-S submit · Esc cancel ")
                    .dim(),
            );
        let inner = block.inner(area);
        f.render_widget(block, area);
        let mut lines: Vec<Line> = Vec::new();
        if !self.intro.is_empty() {
            for l in self.intro.lines() {
                lines.push(Line::from(l.to_string()).fg(Color::Gray));
            }
            lines.push(Line::default());
        }
        let label_w = self.fields.iter().map(|f| f.label.chars().count()).max().unwrap_or(0).min(28);
        for (i, fld) in self.fields.iter().enumerate() {
            let focused = i == self.focus;
            let lab = Span::styled(
                format!("{:>w$}  ", fld.label, w = label_w),
                if focused {
                    Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::new()
                },
            );
            let cursor = if focused { "▏" } else { "" };
            match &fld.kind {
                Kind::Text => lines.push(Line::from(vec![lab, Span::raw(format!("{}{cursor}", *fld.value))])),
                Kind::Secret => lines.push(Line::from(vec![
                    lab,
                    Span::raw(format!("{}{cursor}", "•".repeat(fld.value.chars().count()))),
                ])),
                Kind::Toggle => lines.push(Line::from(vec![
                    lab,
                    Span::raw(if &*fld.value == "true" { "[x]" } else { "[ ]" }),
                ])),
                Kind::Choice(o) => lines.push(Line::from(vec![
                    lab,
                    Span::raw(format!("◂ {} ▸", o.get(fld.choice).map(String::as_str).unwrap_or(""))),
                ])),
                Kind::Multi => {
                    lines.push(Line::from(vec![lab, Span::raw("(Enter: new line, Tab: next field)").dim()]));
                    let all: Vec<&str> = fld.value.split('\n').collect();
                    let start = all.len().saturating_sub(5);
                    for (j, l) in all[start..].iter().enumerate() {
                        let last = start + j + 1 == all.len();
                        lines.push(Line::from(format!(
                            "{:w$}  {l}{}",
                            "",
                            if last { cursor } else { "" },
                            w = label_w
                        )));
                    }
                    for _ in all.len() - start..5 {
                        lines.push(Line::default());
                    }
                }
            }
        }
        if let Some(h) = self.fields.get(self.focus).map(|f| &f.help).filter(|h| !h.is_empty()) {
            lines.push(Line::default());
            lines.push(Line::from(h.clone()).fg(Color::Cyan));
        }
        if let Some(e) = &self.error {
            lines.push(Line::default());
            lines.push(Line::from(e.clone()).fg(Color::Red));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

pub struct Viewer {
    pub title: String,
    pub body: Zeroizing<String>,
    pub scroll: u16,
    pub error: bool,
}

impl Viewer {
    pub fn key(&mut self, k: KeyEvent) -> bool {
        let max = self.body.lines().count().saturating_sub(5) as u16;
        match k.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => return true,
            KeyCode::Down | KeyCode::Char('j') => self.scroll = (self.scroll + 1).min(max),
            KeyCode::Up | KeyCode::Char('k') => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => self.scroll = (self.scroll + 20).min(max),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(20),
            KeyCode::Home => self.scroll = 0,
            KeyCode::End => self.scroll = max,
            _ => {}
        }
        false
    }

    pub fn draw(&self, f: &mut Frame, area: Rect) {
        let width = self.body.lines().map(|l| l.chars().count()).max().unwrap_or(20) as u16 + 4;
        let height = self.body.lines().count() as u16 + 3;
        let area = centered(area, width.clamp(40, area.width), height.max(5));
        f.render_widget(Clear, area);
        let color = if self.error { Color::Red } else { Color::Cyan };
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(color))
            .title(format!(" {} ", self.title))
            .title_bottom(Line::from(" ↑↓ PgUp PgDn scroll · Enter/Esc close ").dim());
        f.render_widget(
            Paragraph::new(Text::raw(self.body.as_str())).block(block).scroll((self.scroll, 0)),
            area,
        );
    }
}

pub type OnYes = Box<dyn FnOnce(&mut App)>;

pub struct Confirm {
    pub title: String,
    pub body: String,
    pub on_yes: Option<OnYes>,
}

impl Confirm {
    pub fn draw(&self, f: &mut Frame, area: Rect) {
        let width = self.body.lines().map(|l| l.chars().count()).max().unwrap_or(20) as u16 + 4;
        let area = centered(area, width.clamp(40, area.width), self.body.lines().count() as u16 + 5);
        f.render_widget(Clear, area);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Color::Yellow))
            .title(format!(" {} ", self.title))
            .title_bottom(Line::from(" y: yes · n/Esc: no ").bold());
        f.render_widget(Paragraph::new(self.body.as_str()).block(block).wrap(Wrap { trim: false }), area);
    }
}

pub enum Modal {
    Form(Form),
    View(Viewer),
    Confirm(Confirm),
}

/// A rectangle of at most `w` x `h`, centered in `area`.
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let [r] = Layout::vertical([Constraint::Length(h.min(area.height))]).flex(Flex::Center).areas(area);
    let [r] = Layout::horizontal([Constraint::Length(w.min(area.width))]).flex(Flex::Center).areas(r);
    r
}
