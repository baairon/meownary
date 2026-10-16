//! The interactive view. This is a working skeleton: it streams a scan, lists
//! files with their format and finding counts, and shows the help overlay. The
//! detail/hex view, buckets, and in-app editing are wired in by their stream;
//! the keymap and theme they build on live beside this file.

#![cfg(feature = "tui")]

use std::io;
use std::path::Path;
use std::time::Duration;

use ratatui::DefaultTerminal;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use crate::model::FileReport;
use crate::scan::{self, ScanEvent, ScanOpts};

use super::{keymap, logo, theme};

/// Run the interactive view over `path`. Sets up and tears down the terminal.
pub fn run(path: &Path) -> io::Result<()> {
    let (rx, _handle) = scan::scan(path, ScanOpts::default());
    let mut terminal = ratatui::init();
    let result = App::new().run(&mut terminal, rx);
    ratatui::restore();
    result
}

struct App {
    reports: Vec<FileReport>,
    state: ListState,
    scanning: bool,
    show_help: bool,
}

impl App {
    fn new() -> Self {
        Self {
            reports: Vec::new(),
            state: ListState::default(),
            scanning: true,
            show_help: false,
        }
    }

    fn run(
        &mut self,
        terminal: &mut DefaultTerminal,
        rx: std::sync::mpsc::Receiver<ScanEvent>,
    ) -> io::Result<()> {
        loop {
            // Drain whatever the scan has produced without blocking the UI.
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    ScanEvent::Found(r) => {
                        self.reports.push(*r);
                        if self.state.selected().is_none() {
                            self.state.select(Some(0));
                        }
                    }
                    ScanEvent::Done => self.scanning = false,
                }
            }

            terminal.draw(|f| self.draw(f))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press && self.on_key(key.code) {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Handle a key. Returns true to quit.
    fn on_key(&mut self, code: KeyCode) -> bool {
        if self.show_help {
            // Any key closes help.
            self.show_help = false;
            return false;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            _ => {}
        }
        false
    }

    fn move_by(&mut self, delta: isize) {
        if self.reports.is_empty() {
            return;
        }
        let len = self.reports.len() as isize;
        let cur = self.state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(len);
        self.state.select(Some(next as usize));
    }

    fn draw(&mut self, frame: &mut Frame) {
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());

        self.draw_header(frame, chunks[0]);
        self.draw_list(frame, chunks[1]);
        self.draw_footer(frame, chunks[2]);

        if self.show_help {
            self.draw_help(frame, chunks[1]);
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let word = gradient_wordmark("meownary");
        let status = if self.scanning {
            format!("scanning... {} file(s)", self.reports.len())
        } else {
            let flagged = self
                .reports
                .iter()
                .filter(|r| !r.findings.is_empty())
                .count();
            format!("{} file(s), {} with findings", self.reports.len(), flagged)
        };
        let lines = vec![
            Line::from(word),
            Line::from(Span::styled(status, Style::new().fg(theme::ALT))),
        ];
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn draw_list(&mut self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self.reports.iter().map(row).collect();
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::new().fg(theme::RULE)),
            )
            .highlight_style(Style::new().fg(theme::BRIGHT).add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, area, &mut self.state);
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let mut spans = Vec::new();
        for (i, hint) in keymap::footer_hints("scan").iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled("  ", Style::new().fg(theme::RULE)));
            }
            spans.push(Span::styled(hint.key, Style::new().fg(theme::ALT)));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(hint.label, Style::new().fg(theme::RULE)));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_help(&self, frame: &mut Frame, area: Rect) {
        let mut lines: Vec<Line> = Vec::new();
        for art in logo::LOGO {
            lines.push(Line::from(Span::styled(
                *art,
                Style::new().fg(theme::ACCENT),
            )));
        }
        lines.push(Line::from(""));
        for (title, hints) in keymap::HELP_GROUPS {
            lines.push(Line::from(Span::styled(
                (*title).to_string(),
                Style::new().fg(theme::BRIGHT).add_modifier(Modifier::BOLD),
            )));
            for hint in *hints {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<12}", hint.key), Style::new().fg(theme::ALT)),
                    Span::styled(hint.label, Style::new().fg(theme::TEXT)),
                ]));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "originals go to trash, u undoes. any key closes.",
            Style::new().fg(theme::RULE),
        )));

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(theme::ACCENT))
            .title(" keys ");
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }
}

/// One list row: pointer-free; the list adds the highlight symbol.
fn row(r: &FileReport) -> ListItem<'static> {
    let fmt = r.format.clone().unwrap_or_else(|| "unknown".to_string());
    let mut spans = vec![
        Span::styled(r.path.display().to_string(), Style::new().fg(theme::TEXT)),
        Span::raw("  "),
        Span::styled(format!("[{fmt}]"), Style::new().fg(theme::ALT)),
    ];
    if let Some(sev) = r.max_severity() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("{} finding(s)", r.findings.len()),
            Style::new().fg(theme::severity_color(sev)),
        ));
    }
    if r.partial {
        spans.push(Span::styled("  (partial)", Style::new().fg(theme::WARN)));
    }
    ListItem::new(Line::from(spans))
}

/// Color the wordmark along the accent ramp, one step per character.
fn gradient_wordmark(text: &str) -> Line<'static> {
    let n = text.chars().count().max(1);
    let spans: Vec<Span> = text
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let t = i as f32 / n as f32;
            let color = theme::lerp(theme::ACCENT_RAMP[0], theme::ACCENT_RAMP[1], t);
            Span::styled(
                c.to_string(),
                Style::new().fg(color).add_modifier(Modifier::BOLD),
            )
        })
        .collect();
    Line::from(spans)
}
