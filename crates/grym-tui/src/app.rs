use std::time::{Duration, Instant};

use crate::ui;
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, MouseButton, MouseEvent, MouseEventKind,
};
use grym_core::{Finding, Severity};
use grym_storage::{FindingStore, MemoryFindingStore};
use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::layout::Rect;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Tab {
    #[default]
    Dashboard,
    Scanner,
    Findings,
    Payloads,
    Plan,
    Logs,
    Config,
}

impl Tab {
    pub fn label(&self) -> &'static str {
        match self {
            Tab::Dashboard => " DASHBOARD ",
            Tab::Scanner => " SCANNER ",
            Tab::Findings => " FINDINGS ",
            Tab::Payloads => " PAYLOADS ",
            Tab::Plan => " PLAN ",
            Tab::Logs => " LOGS ",
            Tab::Config => " CONFIG ",
        }
    }
}

/// All tabs in display order.
pub const TAB_ORDER: [Tab; 7] = [
    Tab::Dashboard,
    Tab::Scanner,
    Tab::Findings,
    Tab::Payloads,
    Tab::Plan,
    Tab::Logs,
    Tab::Config,
];

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
    pub help_scroll: usize,
    pub last_tick: Instant,
    pub tick_rate: Duration,
    pub finding_store: MemoryFindingStore,
    pub show_help: bool,
    pub mouse_enabled: bool,
    // Payloads tab state.
    pub payload_sets: Vec<grym_web_scanner::playbook::PayloadSet>,
    pub selected_payload_set: usize,
    pub payload_scroll: u16,
    // Plan tab state.
    pub plan: grym_web_scanner::plan::EngagementPlan,
    pub plan_scroll: u16,
    // Hit-areas populated by the renderer for mouse interaction.
    pub tab_area: Option<Rect>,
    pub findings_list_area: Option<Rect>,
    pub payload_set_list_area: Option<Rect>,
    pub logs_area: Option<Rect>,
    pub help_close_area: Option<Rect>,
    pub footer_help_area: Option<Rect>,
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
            help_scroll: 0,
            last_tick: Instant::now(),
            tick_rate: Duration::from_millis(250),
            finding_store: store,
            show_help: false,
            mouse_enabled: true,
            payload_sets: grym_web_scanner::playbook::payload_sets(),
            selected_payload_set: 0,
            payload_scroll: 0,
            plan: Self::build_plan(),
            plan_scroll: 0,
            tab_area: None,
            findings_list_area: None,
            payload_set_list_area: None,
            logs_area: None,
            help_close_area: None,
            footer_help_area: None,
        }
    }

    /// Generate an engagement plan from the persisted settings scope.
    fn build_plan() -> grym_web_scanner::plan::EngagementPlan {
        let settings = grym_core::settings::GrymSettings::load();
        let target = settings.scope.allow.first().cloned().unwrap_or_default();
        let limits = grym_web_scanner::plan::PlanLimits {
            max_tier: settings.scope.max_tier.min(4),
            deepness: settings.scope.deepness.clone(),
        };
        let profile = grym_web_scanner::plan::TargetProfile {
            base_url: target,
            technologies: Vec::new(),
            authenticated: settings.scope.authorization_attested,
            notes: Vec::new(),
            engagement_id: settings.scope.engagement_id.clone(),
        };
        grym_web_scanner::plan::generate(&profile, &limits)
    }

    /// The payload set currently selected in the Payloads tab.
    pub fn current_payload_set(&self) -> Option<&grym_web_scanner::playbook::PayloadSet> {
        self.payload_sets.get(self.selected_payload_set)
    }

    pub async fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> anyhow::Result<()>
    where
        B::Error: Send + Sync + 'static,
    {
        let tick_rate = self.tick_rate;
        loop {
            terminal.draw(|frame| ui::render(frame, self))?;

            if event::poll(tick_rate)? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => self.handle_key(key.code),
                    Event::Mouse(mouse) if self.mouse_enabled => self.handle_mouse(mouse),
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }

            self.update_metrics();

            if self.should_quit {
                break;
            }
        }
        Ok(())
    }

    fn handle_key(&mut self, key: KeyCode) {
        if self.show_help {
            match key {
                KeyCode::Char('q') | KeyCode::Esc => self.show_help = false,
                KeyCode::Char('h') => self.show_help = false,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = self.help_scroll.saturating_add(1)
                }
                KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(10),
                KeyCode::PageDown => self.help_scroll = self.help_scroll.saturating_add(10),
                KeyCode::Home => self.help_scroll = 0,
                KeyCode::End => self.help_scroll = usize::MAX,
                _ => {}
            }
            return;
        }

        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('h') => {
                self.show_help = true;
                self.help_scroll = 0;
            }
            KeyCode::Char('1') => self.active_tab = Tab::Dashboard,
            KeyCode::Char('2') => self.active_tab = Tab::Scanner,
            KeyCode::Char('3') => self.active_tab = Tab::Findings,
            KeyCode::Char('4') => self.active_tab = Tab::Payloads,
            KeyCode::Char('5') => self.active_tab = Tab::Plan,
            KeyCode::Char('6') => self.active_tab = Tab::Logs,
            KeyCode::Char('7') => self.active_tab = Tab::Config,
            KeyCode::Right | KeyCode::Tab => {
                let tabs = &TAB_ORDER;
                if let Some(pos) = tabs.iter().position(|t| *t == self.active_tab) {
                    self.active_tab = tabs[(pos + 1) % tabs.len()];
                }
            }
            KeyCode::Left | KeyCode::BackTab => {
                let tabs = &TAB_ORDER;
                if let Some(pos) = tabs.iter().position(|t| *t == self.active_tab) {
                    self.active_tab = if pos == 0 {
                        tabs[tabs.len() - 1]
                    } else {
                        tabs[pos - 1]
                    };
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.active_tab == Tab::Logs && self.log_scroll > 0 {
                    self.log_scroll -= 1;
                }
                if self.active_tab == Tab::Findings {
                    self.selected_finding = self.selected_finding.map(|i| i.saturating_sub(1));
                }
                if self.active_tab == Tab::Payloads {
                    self.selected_payload_set = self.selected_payload_set.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.active_tab == Tab::Logs {
                    self.log_scroll += 1;
                }
                if self.active_tab == Tab::Findings {
                    self.selected_finding = Some(
                        self.selected_finding
                            .unwrap_or(0)
                            .saturating_add(1)
                            .min(self.findings.len().saturating_sub(1)),
                    );
                }
                if self.active_tab == Tab::Payloads {
                    let max = self.payload_sets.len().saturating_sub(1);
                    self.selected_payload_set = (self.selected_payload_set + 1).min(max);
                }
            }
            KeyCode::PageUp => {
                if self.active_tab == Tab::Logs {
                    self.log_scroll = self.log_scroll.saturating_sub(5);
                }
                if self.active_tab == Tab::Payloads {
                    self.payload_scroll = self.payload_scroll.saturating_sub(10);
                }
                if self.active_tab == Tab::Plan {
                    self.plan_scroll = self.plan_scroll.saturating_sub(10);
                }
            }
            KeyCode::PageDown => {
                if self.active_tab == Tab::Logs {
                    self.log_scroll = self.log_scroll.saturating_add(5);
                }
                if self.active_tab == Tab::Payloads {
                    self.payload_scroll = self.payload_scroll.saturating_add(10);
                }
                if self.active_tab == Tab::Plan {
                    self.plan_scroll = self.plan_scroll.saturating_add(10);
                }
            }
            KeyCode::Enter => {
                if self.active_tab == Tab::Findings
                    && let Some(idx) = self.selected_finding
                    && idx < self.findings.len()
                {
                    let finding = &self.findings[idx];
                    self.logs.push(LogEntry {
                        timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
                        level: "INFO".into(),
                        module: "tui".into(),
                        message: format!(
                            "Viewing finding: {} [{}]",
                            finding.title, finding.affected_asset.identifier
                        ),
                    });
                }
            }
            _ => {}
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) {
        let (x, y) = (mouse.column as u16, mouse.row as u16);

        // Help overlay: close on left-click inside close button, or any left click.
        if self.show_help {
            match mouse.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    if self
                        .help_close_area
                        .map_or(true, |r| r.contains(ratatui::layout::Position { x, y }))
                    {
                        self.show_help = false;
                    }
                }
                MouseEventKind::ScrollUp => self.help_scroll = self.help_scroll.saturating_sub(3),
                MouseEventKind::ScrollDown => self.help_scroll = self.help_scroll.saturating_add(3),
                _ => {}
            }
            return;
        }

        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                // Tab bar click.
                if let Some(area) = self.tab_area {
                    if area.contains(ratatui::layout::Position { x, y }) {
                        // Approximate equal-width tab cells inside the border.
                        let inner_width = area.width.saturating_sub(2).max(1);
                        let cell_width = inner_width / TAB_ORDER.len() as u16;
                        let rel_x = x.saturating_sub(area.x + 1);
                        let idx = (rel_x / cell_width.max(1)) as usize;
                        if idx < TAB_ORDER.len() {
                            self.active_tab = TAB_ORDER[idx];
                        }
                        return;
                    }
                }

                // Payload set list click.
                if self.active_tab == Tab::Payloads {
                    if let Some(area) = self.payload_set_list_area {
                        if area.contains(ratatui::layout::Position { x, y })
                            && !self.payload_sets.is_empty()
                        {
                            let inner_y = y.saturating_sub(area.y + 1) as usize;
                            let max = self.payload_sets.len() - 1;
                            self.selected_payload_set = inner_y.min(max);
                            return;
                        }
                    }
                }

                // Findings list click.
                if self.active_tab == Tab::Findings {
                    if let Some(area) = self.findings_list_area {
                        if area.contains(ratatui::layout::Position { x, y })
                            && !self.findings.is_empty()
                        {
                            let inner_y = y.saturating_sub(area.y + 1);
                            let idx = inner_y as usize;
                            if idx < self.findings.len() {
                                self.selected_finding = Some(idx);
                                let finding = &self.findings[idx];
                                self.logs.push(LogEntry {
                                    timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
                                    level: "INFO".into(),
                                    module: "tui".into(),
                                    message: format!(
                                        "Viewing finding: {} [{}]",
                                        finding.title, finding.affected_asset.identifier
                                    ),
                                });
                            }
                            return;
                        }
                    }
                }

                // Footer help button click.
                if let Some(area) = self.footer_help_area {
                    if area.contains(ratatui::layout::Position { x, y }) {
                        self.show_help = true;
                        self.help_scroll = 0;
                        return;
                    }
                }
            }
            MouseEventKind::ScrollUp => {
                if self.active_tab == Tab::Logs {
                    self.log_scroll = self.log_scroll.saturating_sub(3);
                } else if self.active_tab == Tab::Findings {
                    self.selected_finding = self.selected_finding.map(|i| i.saturating_sub(1));
                } else if self.active_tab == Tab::Payloads {
                    self.payload_scroll = self.payload_scroll.saturating_sub(3);
                } else if self.active_tab == Tab::Plan {
                    self.plan_scroll = self.plan_scroll.saturating_sub(3);
                }
            }
            MouseEventKind::ScrollDown => {
                if self.active_tab == Tab::Logs {
                    self.log_scroll = self.log_scroll.saturating_add(3);
                } else if self.active_tab == Tab::Findings {
                    self.selected_finding = Some(
                        self.selected_finding
                            .unwrap_or(0)
                            .saturating_add(1)
                            .min(self.findings.len().saturating_sub(1)),
                    );
                } else if self.active_tab == Tab::Payloads {
                    self.payload_scroll = self.payload_scroll.saturating_add(3);
                } else if self.active_tab == Tab::Plan {
                    self.plan_scroll = self.plan_scroll.saturating_add(3);
                }
            }
            _ => {}
        }
    }

    fn update_metrics(&mut self) {
        if let Ok(all) = self.finding_store.all() {
            self.findings = all;
            self.metrics.findings_count = self.findings.len() as u64;
            self.metrics.high_severity = self
                .findings
                .iter()
                .filter(|f| f.severity >= Severity::High)
                .count() as u64;
            self.metrics.medium_severity = self
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count() as u64;
            self.metrics.low_severity = self
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count() as u64;
            self.metrics.info_count = self
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count() as u64;
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
