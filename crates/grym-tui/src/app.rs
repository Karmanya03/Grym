use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use grym_core::{Finding, Severity};
use grym_storage::{FindingStore, MemoryFindingStore};
use ratatui::Terminal;
use ratatui::backend::Backend;
use crate::ui;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Tab {
    #[default]
    Dashboard,
    Scanner,
    Findings,
    Logs,
    Config,
}

impl Tab {
    pub fn label(&self) -> &'static str {
        match self {
            Tab::Dashboard => " DASHBOARD ",
            Tab::Scanner => " SCANNER ",
            Tab::Findings => " FINDINGS ",
            Tab::Logs => " LOGS ",
            Tab::Config => " CONFIG ",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScanMetrics {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub findings_count: u64,
    pub high_severity: u64,
    pub medium_severity: u64,
    pub low_severity: u64,
    pub info_count: u64,
    pub scan_progress_percent: u8,
    pub active_modules: Vec<ModuleStatus>,
    pub elapsed: Duration,
    pub current_target: String,
}

#[derive(Clone, Debug)]
pub struct ModuleStatus {
    pub name: String,
    pub running: bool,
    pub completed: bool,
    pub findings: u64,
    pub progress: u8,
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub module: String,
    pub message: String,
}

#[derive(Debug)]
pub struct GrymTuiApp {
    pub active_tab: Tab,
    pub should_quit: bool,
    pub metrics: ScanMetrics,
    pub findings: Vec<Finding>,
    pub logs: Vec<LogEntry>,
    pub selected_finding: Option<usize>,
    pub log_scroll: usize,
    pub finding_scroll: usize,
    pub last_tick: Instant,
    pub tick_rate: Duration,
    pub finding_store: MemoryFindingStore,
    pub show_help: bool,
}

impl Default for GrymTuiApp {
    fn default() -> Self {
        Self::new()
    }
}

impl GrymTuiApp {
    pub fn new() -> Self {
        let store = MemoryFindingStore::default();
        Self {
            active_tab: Tab::Dashboard,
            should_quit: false,
            metrics: ScanMetrics::default(),
            findings: Vec::new(),
            logs: Vec::new(),
            selected_finding: None,
            log_scroll: 0,
            finding_scroll: 0,
            last_tick: Instant::now(),
            tick_rate: Duration::from_millis(250),
            finding_store: store,
            show_help: false,
        }
    }

    pub async fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> anyhow::Result<()> {
        let tick_rate = self.tick_rate;
        loop {
            terminal.draw(|frame| ui::render(frame, self))?;

            if event::poll(tick_rate)?
                && let Event::Key(key) = event::read()?
                    && key.kind == KeyEventKind::Press {
                        self.handle_key(key.code);
                    }

            self.update_metrics();

            if self.should_quit {
                break;
            }
        }
        Ok(())
    }

    fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.show_help {
                    self.show_help = false;
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Char('h') => self.show_help = !self.show_help,
            KeyCode::Char('1') => self.active_tab = Tab::Dashboard,
            KeyCode::Char('2') => self.active_tab = Tab::Scanner,
            KeyCode::Char('3') => self.active_tab = Tab::Findings,
            KeyCode::Char('4') => self.active_tab = Tab::Logs,
            KeyCode::Char('5') => self.active_tab = Tab::Config,
            KeyCode::Right | KeyCode::Tab => {
                let tabs = &[Tab::Dashboard, Tab::Scanner, Tab::Findings, Tab::Logs, Tab::Config];
                if let Some(pos) = tabs.iter().position(|t| *t == self.active_tab) {
                    self.active_tab = tabs[(pos + 1) % tabs.len()];
                }
            }
            KeyCode::Left | KeyCode::BackTab => {
                let tabs = &[Tab::Dashboard, Tab::Scanner, Tab::Findings, Tab::Logs, Tab::Config];
                if let Some(pos) = tabs.iter().position(|t| *t == self.active_tab) {
                    self.active_tab = if pos == 0 { tabs[tabs.len() - 1] } else { tabs[pos - 1] };
                }
            }
            KeyCode::Up => {
                if self.active_tab == Tab::Logs && self.log_scroll > 0 {
                    self.log_scroll -= 1;
                }
                if self.active_tab == Tab::Findings {
                    self.selected_finding = self.selected_finding.map(|i| i.saturating_sub(1));
                }
            }
            KeyCode::Down => {
                if self.active_tab == Tab::Logs {
                    self.log_scroll += 1;
                }
                if self.active_tab == Tab::Findings {
                    self.selected_finding = Some(self.selected_finding.unwrap_or(0).saturating_add(1).min(self.findings.len().saturating_sub(1)));
                }
            }
            KeyCode::Enter => {
                if self.active_tab == Tab::Findings
                    && let Some(idx) = self.selected_finding
                        && idx < self.findings.len() {
                            let finding = &self.findings[idx];
                            self.logs.push(LogEntry {
                                timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
                                level: "INFO".into(),
                                module: "tui".into(),
                                message: format!("Viewing finding: {} [{}]", finding.title, finding.affected_asset.identifier),
                            });
                        }
            }
            _ => {}
        }
    }

    fn update_metrics(&mut self) {
        if let Ok(all) = self.finding_store.all() {
            self.findings = all;
            self.metrics.findings_count = self.findings.len() as u64;
            self.metrics.high_severity = self.findings.iter().filter(|f| f.severity >= Severity::High).count() as u64;
            self.metrics.medium_severity = self.findings.iter().filter(|f| f.severity == Severity::Medium).count() as u64;
            self.metrics.low_severity = self.findings.iter().filter(|f| f.severity == Severity::Low).count() as u64;
            self.metrics.info_count = self.findings.iter().filter(|f| f.severity == Severity::Info).count() as u64;
        }
    }

    pub fn add_log(&mut self, level: &str, module: &str, message: String) {
        self.logs.push(LogEntry {
            timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
            level: level.into(),
            module: module.into(),
            message,
        });
        if self.logs.len() > 1000 {
            self.logs.remove(0);
        }
        self.log_scroll = self.logs.len().saturating_sub(1);
    }
}
