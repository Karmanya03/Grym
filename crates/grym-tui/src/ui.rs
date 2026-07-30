use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Gauge, List, ListItem,
        Paragraph, Tabs, Wrap,
    },
};
use crate::app::{GrymTuiApp, Tab};

pub fn render(frame: &mut Frame, app: &GrymTuiApp) {
    if app.show_help {
        render_help_overlay(frame);
        return;
    }

    let area = frame.area();
    let vertical = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ]);
    let [header_area, body_area, footer_area] = vertical.areas(area);

    render_header(frame, header_area, app);
    render_body(frame, body_area, app);
    render_footer(frame, footer_area, app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &GrymTuiApp) {
    let title_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::new().fg(Color::Cyan))
        .title_alignment(ratatui::layout::Alignment::Center)
        .title(Span::styled(
            " GRYM — Advanced Web/App PT Automation Toolkit ",
            Style::new()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));

    let tabs = Tabs::new(vec![
        Tab::Dashboard.label(),
        Tab::Scanner.label(),
        Tab::Findings.label(),
        Tab::Logs.label(),
        Tab::Config.label(),
    ])
    .select(match app.active_tab {
        Tab::Dashboard => 0,
        Tab::Scanner => 1,
        Tab::Findings => 2,
        Tab::Logs => 3,
        Tab::Config => 4,
    })
    .block(title_block)
    .highlight_style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    .style(Style::new().fg(Color::DarkGray));

    frame.render_widget(tabs, area);
}

fn render_footer(frame: &mut Frame, area: Rect, _app: &GrymTuiApp) {
    let hints = Line::from(vec![
        Span::styled(" [1-5] Tabs ", Style::new().fg(Color::Cyan)),
        Span::styled(" [↑↓] Navigate ", Style::new().fg(Color::Green)),
        Span::styled(" [Tab] Next Tab ", Style::new().fg(Color::Yellow)),
        Span::styled(" [h] Help ", Style::new().fg(Color::Magenta)),
        Span::styled(" [q] Quit ", Style::new().fg(Color::Red)),
    ]);
    let footer = Paragraph::new(hints)
        .block(Block::default().borders(Borders::ALL).border_style(Style::new().fg(Color::DarkGray)))
        .style(Style::new().fg(Color::White));
    frame.render_widget(footer, area);
}

fn render_body(frame: &mut Frame, area: Rect, app: &GrymTuiApp) {
    match app.active_tab {
        Tab::Dashboard => render_dashboard(frame, area, app),
        Tab::Scanner => render_scanner(frame, area, app),
        Tab::Findings => render_findings(frame, area, app),
        Tab::Logs => render_logs(frame, area, app),
        Tab::Config => render_config(frame, area, app),
    }
}

fn render_dashboard(frame: &mut Frame, area: Rect, app: &GrymTuiApp) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .areas::<3>(area);

    let [status_area, stats_area, modules_area] = chunks;

    let status = format!(
        "Active Scan: {} | Requests: {} | Blocked: {} | Elapsed: {}s",
        if app.metrics.active_modules.iter().any(|m| m.running) { "RUNNING" } else { "IDLE" },
        app.metrics.total_requests,
        app.metrics.blocked_requests,
        app.metrics.elapsed.as_secs(),
    );
    let status_widget = Paragraph::new(Line::from(Span::styled(status, Style::new().fg(Color::Green))))
        .block(Block::default().borders(Borders::ALL).title(" Status ").border_style(Style::new().fg(Color::Cyan)));
    frame.render_widget(status_widget, status_area);

    let stats = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
    ])
    .areas::<4>(stats_area);

    let blocks = [
        (" Critical ", app.metrics.high_severity, Color::Red),
        (" Medium ", app.metrics.medium_severity, Color::Yellow),
        (" Low ", app.metrics.low_severity, Color::Blue),
        (" Info ", app.metrics.info_count, Color::White),
    ];

    for (i, (title, count, color)) in blocks.iter().enumerate() {
        let widget = Paragraph::new(Line::from(Span::styled(
            format!("{}\n{}", title, count),
            Style::new().fg(*color).add_modifier(Modifier::BOLD),
        )))
        .block(Block::default().borders(Borders::ALL).border_style(Style::new().fg(*color)))
        .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(widget, stats[i]);
    }

    let modules: Vec<ListItem> = app.metrics.active_modules.iter().map(|m| {
        let icon = if m.completed { "✓" } else if m.running { "▶" } else { "○" };
        let color = if m.completed { Color::Green } else if m.running { Color::Yellow } else { Color::DarkGray };
        ListItem::new(Line::from(Span::styled(
            format!(" {} {} — {} findings ({}%)", icon, m.name, m.findings, m.progress),
            Style::new().fg(color),
        )))
    }).collect();

    let module_list = if modules.is_empty() {
        List::new(vec![ListItem::new(Line::from(Span::styled(
            " No active modules — use Tab 2 (Scanner) to start a scan",
            Style::new().fg(Color::DarkGray),
        )))])
    } else {
        List::new(modules)
    };

    let module_widget = module_list
        .block(Block::default().borders(Borders::ALL).title(" Modules ").border_style(Style::new().fg(Color::Cyan)));
    frame.render_widget(module_widget, modules_area);
}

fn render_scanner(frame: &mut Frame, area: Rect, app: &GrymTuiApp) {
    let chunks = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Min(0),
    ])
    .areas::<3>(area);

    let [progress_area, target_area, module_area] = chunks;

    let progress = app.metrics.scan_progress_percent;
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Scan Progress "))
        .gauge_style(Style::new().fg(Color::Cyan).bg(Color::Black).add_modifier(Modifier::BOLD))
        .percent(progress as u16)
        .label(format!("{}% — {} findings", progress, app.metrics.findings_count));
    frame.render_widget(gauge, progress_area);

    let target_info = format!(
        "Target: {} | Requests: {} | Rate: {:.1}/s | Modules: {}",
        if app.metrics.current_target.is_empty() { "none" } else { &app.metrics.current_target },
        app.metrics.total_requests,
        if app.metrics.elapsed.as_secs() > 0 { app.metrics.total_requests as f64 / app.metrics.elapsed.as_secs() as f64 } else { 0.0 },
        app.metrics.active_modules.len(),
    );
    let target_widget = Paragraph::new(Line::from(Span::styled(target_info, Style::new().fg(Color::White))))
        .block(Block::default().borders(Borders::ALL).title(" Target Info ").border_style(Style::new().fg(Color::Yellow)));
    frame.render_widget(target_widget, target_area);

    let module_items: Vec<ListItem> = [
        ("DNS Enumeration", "Resolve subdomains via CT logs, brute force", false),
        ("Port Scanner", "Async TCP scan of common ports", false),
        ("Web Crawler", "SPA-aware JS-rendered crawling", false),
        ("Tech Fingerprint", "Header/cookie/favicon based tech detection", false),
        ("Vulnerability Scan", "SQLi, XSS, SSTI, JWT, SSRF, CORS checks", false),
        ("CVE Correlation", "Multi-source NVD/OSV/KEV/GHSA matching", false),
    ].iter().map(|(name, desc, _)| {
        ListItem::new(Line::from(vec![
            Span::styled(" ○ ", Style::new().fg(Color::DarkGray)),
            Span::styled(*name, Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(" — ", Style::new().fg(Color::DarkGray)),
            Span::styled(*desc, Style::new().fg(Color::White)),
        ]))
    }).collect();

    let module_list = List::new(module_items)
        .block(Block::default().borders(Borders::ALL).title(" Available Scanner Modules ").border_style(Style::new().fg(Color::Cyan)));
    frame.render_widget(module_list, module_area);
}

fn render_findings(frame: &mut Frame, area: Rect, app: &GrymTuiApp) {
    if app.findings.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No findings yet. Run a scan from the Scanner tab.",
            Style::new().fg(Color::DarkGray),
        )))
        .block(Block::default().borders(Borders::ALL).title(" Findings Explorer ").border_style(Style::new().fg(Color::Cyan)));
        frame.render_widget(empty, area);
        return;
    }

    let chunks = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
        .areas::<2>(area);

    let [list_area, detail_area] = chunks;

    let items: Vec<ListItem> = app.findings.iter().enumerate().map(|(i, f)| {
        let severity_color = match f.severity {
            grym_core::Severity::Critical => Color::Red,
            grym_core::Severity::High => Color::LightRed,
            grym_core::Severity::Medium => Color::Yellow,
            grym_core::Severity::Low => Color::Blue,
            grym_core::Severity::Info => Color::White,
        };
        let confidence_icon = match f.confidence {
            grym_core::Confidence::Confirmed => "✓",
            grym_core::Confidence::Likely => "~",
            grym_core::Confidence::Possible => "?",
        };
        ListItem::new(Line::from(vec![
            Span::styled(format!("{:>3} ", i + 1), Style::new().fg(Color::DarkGray)),
            Span::styled(format!("{} ", confidence_icon), Style::new().fg(severity_color)),
            Span::styled(format!("{:?} ", f.severity), Style::new().fg(severity_color).add_modifier(Modifier::BOLD)),
            Span::styled(&f.title, Style::new().fg(Color::White)),
        ]))
    }).collect();

    let selected_style = Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD);
    let findings_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Findings List ").border_style(Style::new().fg(Color::Cyan)))
        .highlight_style(selected_style)
        .highlight_symbol("> ");

    frame.render_stateful_widget(findings_list, list_area, &mut ratatui::widgets::ListState::default().with_selected(app.selected_finding));

    if let Some(idx) = app.selected_finding
        && let Some(finding) = app.findings.get(idx) {
            let detail = format!(
                "Title: {}\nSeverity: {:?}\nConfidence: {:?}\nAsset: {}\nCategories: {}\nCWE: {:?}\nATT&CK: {:?}\nCVSS: {:?} ({:?})\n\nRemediation: {}\n\nReferences: {}",
                finding.title,
                finding.severity,
                finding.confidence,
                finding.affected_asset.identifier,
                finding.categories.join(", "),
                finding.cwe_ids,
                finding.attack_techniques,
                finding.cvss_vector,
                finding.cvss_score,
                finding.remediation,
                finding.references.join("\n  "),
            );
            let detail_widget = Paragraph::new(detail)
                .block(Block::default().borders(Borders::ALL).title(" Finding Details ").border_style(Style::new().fg(Color::Yellow)))
                .wrap(Wrap { trim: false });
            frame.render_widget(detail_widget, detail_area);
        }
}

fn render_logs(frame: &mut Frame, area: Rect, app: &GrymTuiApp) {
    if app.logs.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No log entries yet.",
            Style::new().fg(Color::DarkGray),
        )))
        .block(Block::default().borders(Borders::ALL).title(" Live Log Stream ").border_style(Style::new().fg(Color::Cyan)));
        frame.render_widget(empty, area);
        return;
    }

    let log_items: Vec<ListItem> = app.logs.iter().rev().skip(app.log_scroll).take(50).map(|entry| {
        let level_color = match entry.level.as_str() {
            "ERROR" => Color::Red,
            "WARN" => Color::Yellow,
            "INFO" => Color::Green,
            "DEBUG" => Color::Blue,
            _ => Color::White,
        };
        ListItem::new(Line::from(vec![
            Span::styled(format!("{} ", entry.timestamp), Style::new().fg(Color::DarkGray)),
            Span::styled(format!("[{:<5}] ", entry.level), Style::new().fg(level_color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{:<20} ", entry.module), Style::new().fg(Color::Cyan)),
            Span::styled(&entry.message, Style::new().fg(Color::White)),
        ]))
    }).collect();

    let log_list = List::new(log_items)
        .block(Block::default().borders(Borders::ALL).title(" Live Log Stream ").border_style(Style::new().fg(Color::Cyan)));
    frame.render_widget(log_list, area);
}

fn render_config(frame: &mut Frame, area: Rect, app: &GrymTuiApp) {
    let chunks = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Min(0),
    ])
    .areas::<3>(area);

    let [tier_area, deepness_area, limits_area] = chunks;

    let tier_info = "\
Technique Tiers:
  [0] Passive Only — OSINT, DNS, CT logs, no packets to target
  [1] Safe Active — Port scan, crawl, fingerprint, read-only
  [2] Standard Detection — Full signature + safe active checks
  [3] Authenticated — Operator-supplied credentials
  [4] Active Validation — OOB-confirmed validation per finding";
    let tier_widget = Paragraph::new(tier_info)
        .block(Block::default().borders(Borders::ALL).title(" Technique Tiers ").border_style(Style::new().fg(Color::Yellow)));
    frame.render_widget(tier_widget, tier_area);

    let deepness_info = "\
Deepness Profiles:
  Quick    — Low-noise, short inventory pass
  Standard — Balanced default
  Deep     — Broader coverage, no risky validation
  Paranoid — Lowest-noise, highest-review profile";
    let deepness_widget = Paragraph::new(deepness_info)
        .block(Block::default().borders(Borders::ALL).title(" Deepness Profiles ").border_style(Style::new().fg(Color::Cyan)));
    frame.render_widget(deepness_widget, deepness_area);

    let limits_info = format!(
        "Limits & Safety:\n  Global Rate: 20 req/s | Per-Host: 3 req/s | Max Redirects: 5\n  Block Threshold: 60% | 5xx Threshold: 5\n  Findings: {} total ({} high, {} med, {} low, {} info)",
        app.metrics.findings_count,
        app.metrics.high_severity,
        app.metrics.medium_severity,
        app.metrics.low_severity,
        app.metrics.info_count,
    );
    let limits_widget = Paragraph::new(limits_info)
        .block(Block::default().borders(Borders::ALL).title(" Limits & Safety ").border_style(Style::new().fg(Color::Green)));
    frame.render_widget(limits_widget, limits_area);
}

fn render_help_overlay(frame: &mut Frame) {
    let area = frame.area();
    let help_text = "\
GRYM TUI — Keyboard Shortcuts

Navigation:
  [1-5] or [Tab/Shift+Tab] — Switch tabs
  [↑/↓]  — Navigate lists
  [Enter] — Select / view details

Actions:
  [h]    — Toggle this help screen
  [q/Esc] — Quit

Tabs:
  1 Dashboard — Overview of scan status, findings count, module states
  2 Scanner   — Configure and launch scan modules
  3 Findings  — Browse and inspect findings with full details
  4 Logs      — Real-time log stream from all modules
  5 Config    — View current technique tier and deepness profiles

Scan Modules:
  • DNS Enumeration — Subdomain discovery via CT logs + brute force
  • Port Scanner    — Async TCP connect scan of common service ports
  • Web Crawler     — SPA-aware crawling with JS endpoint discovery
  • Tech Fingerprint — Header/cookie/favicon technology detection
  • Vuln Scanner    — SQLi, XSS, SSTI, JWT, SSRF, CORS, IDOR checks
  • CVE Correlator  — NVD/OSV/KEV/GHSA multi-source matching

Press [q] or [Esc] to close this help screen.";
    let help_paragraph = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title(" Help ").border_style(Style::new().fg(Color::Yellow)))
        .style(Style::new().fg(Color::White))
        .alignment(ratatui::layout::Alignment::Left);
    frame.render_widget(help_paragraph, area);
}
