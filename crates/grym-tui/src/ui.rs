use crate::app::{GrymTuiApp, Tab};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, Gauge, List, ListItem, Paragraph, Tabs, Wrap},
};

pub fn render(frame: &mut Frame, app: &mut GrymTuiApp) {
    if app.show_help {
        render_help_overlay(frame, app);
        return;
    }

    let area = frame.area();
    let vertical = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ]);
    let [header_area, body_area, footer_area] = vertical.areas(area);

    app.tab_area = Some(header_area);
    render_header(frame, header_area, app);
    render_body(frame, body_area, app);
    render_footer(frame, footer_area, app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
    let title_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::new().fg(Color::Cyan))
        .title_alignment(ratatui::layout::Alignment::Center)
        .title(Span::styled(
            " GRYM — Advanced Web/App PT Automation Toolkit ",
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));

    let tabs = Tabs::new([
        Tab::Dashboard.label(),
        Tab::Scanner.label(),
        Tab::Findings.label(),
        Tab::Payloads.label(),
        Tab::Plan.label(),
        Tab::Logs.label(),
        Tab::Config.label(),
    ])
    .select(match app.active_tab {
        Tab::Dashboard => 0,
        Tab::Scanner => 1,
        Tab::Findings => 2,
        Tab::Payloads => 3,
        Tab::Plan => 4,
        Tab::Logs => 5,
        Tab::Config => 6,
    })
    .block(title_block)
    .highlight_style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    .style(Style::new().fg(Color::DarkGray));

    frame.render_widget(tabs, area);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
    let hints = Line::from(vec![
        Span::styled(" [1-7] Tabs ", Style::new().fg(Color::Cyan)),
        Span::styled(" [↑↓] Navigate ", Style::new().fg(Color::Green)),
        Span::styled(" [Tab] Next Tab ", Style::new().fg(Color::Yellow)),
        Span::styled(" [🖱] Mouse ", Style::new().fg(Color::Blue)),
        Span::styled(" [h] Help ", Style::new().fg(Color::Magenta)),
        Span::styled(" [q] Quit ", Style::new().fg(Color::Red)),
    ]);
    let footer = Paragraph::new(hints)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(Color::DarkGray)),
        )
        .style(Style::new().fg(Color::White));
    frame.render_widget(footer, area);

    // Expose a clickable help button region (roughly the "[h] Help" span).
    let help_width = 9u16;
    let quit_width = 9u16;
    let help_x = area.x + area.width.saturating_sub(help_width + quit_width + 2);
    app.footer_help_area = Some(Rect {
        x: help_x.max(area.x),
        y: area.y,
        width: help_width.min(area.width),
        height: area.height,
    });
}

fn render_body(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
    match app.active_tab {
        Tab::Dashboard => render_dashboard(frame, area, app),
        Tab::Scanner => render_scanner(frame, area, app),
        Tab::Findings => render_findings(frame, area, app),
        Tab::Payloads => render_payloads(frame, area, app),
        Tab::Plan => render_plan(frame, area, app),
        Tab::Logs => render_logs(frame, area, app),
        Tab::Config => render_config(frame, area, app),
    }
}

fn render_dashboard(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .areas::<3>(area);

    let [status_area, stats_area, modules_area] = chunks;

    let status = format!(
        "Active Scan: {} | Requests: {} | Blocked: {} | Elapsed: {}s",
        if app.metrics.active_modules.iter().any(|m| m.running) {
            "RUNNING"
        } else {
            "IDLE"
        },
        app.metrics.total_requests,
        app.metrics.blocked_requests,
        app.metrics.elapsed.as_secs(),
    );
    let status_widget = Paragraph::new(Line::from(Span::styled(
        status,
        Style::new().fg(Color::Green),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Status ")
            .border_style(Style::new().fg(Color::Cyan)),
    );
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
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(*color)),
        )
        .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(widget, stats[i]);
    }

    let modules: Vec<ListItem> = app
        .metrics
        .active_modules
        .iter()
        .map(|m| {
            let icon = if m.completed {
                "✓"
            } else if m.running {
                "▶"
            } else {
                "○"
            };
            let color = if m.completed {
                Color::Green
            } else if m.running {
                Color::Yellow
            } else {
                Color::DarkGray
            };
            ListItem::new(Line::from(Span::styled(
                format!(
                    " {} {} — {} findings ({}%)",
                    icon, m.name, m.findings, m.progress
                ),
                Style::new().fg(color),
            )))
        })
        .collect();

    let module_list = if modules.is_empty() {
        List::new(vec![ListItem::new(Line::from(Span::styled(
            " No active modules — use Tab 2 (Scanner) to start a scan",
            Style::new().fg(Color::DarkGray),
        )))])
    } else {
        List::new(modules)
    };

    let module_widget = module_list.block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Modules ")
            .border_style(Style::new().fg(Color::Cyan)),
    );
    frame.render_widget(module_widget, modules_area);
}

fn render_scanner(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
    let chunks = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Min(0),
    ])
    .areas::<3>(area);

    let [progress_area, target_area, module_area] = chunks;

    let progress = app.metrics.scan_progress_percent;
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Scan Progress "),
        )
        .gauge_style(
            Style::new()
                .fg(Color::Cyan)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .percent(progress as u16)
        .label(format!(
            "{}% — {} findings",
            progress, app.metrics.findings_count
        ));
    frame.render_widget(gauge, progress_area);

    let target_info = format!(
        "Target: {} | Requests: {} | Rate: {:.1}/s | Modules: {}",
        if app.metrics.current_target.is_empty() {
            "none"
        } else {
            &app.metrics.current_target
        },
        app.metrics.total_requests,
        if app.metrics.elapsed.as_secs() > 0 {
            app.metrics.total_requests as f64 / app.metrics.elapsed.as_secs() as f64
        } else {
            0.0
        },
        app.metrics.active_modules.len(),
    );
    let target_widget = Paragraph::new(Line::from(Span::styled(
        target_info,
        Style::new().fg(Color::White),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Target Info ")
            .border_style(Style::new().fg(Color::Yellow)),
    );
    frame.render_widget(target_widget, target_area);

    let module_items: Vec<ListItem> = [
        (
            "DNS Enumeration",
            "Resolve subdomains via CT logs, brute force",
            false,
        ),
        ("Port Scanner", "Async TCP scan of common ports", false),
        ("Web Crawler", "SPA-aware JS-rendered crawling", false),
        (
            "Tech Fingerprint",
            "Header/cookie/favicon based tech detection",
            false,
        ),
        (
            "Vulnerability Scan",
            "SQLi, XSS, SSTI, JWT, SSRF, CORS checks",
            false,
        ),
        (
            "CVE Correlation",
            "Multi-source NVD/OSV/KEV/GHSA matching",
            false,
        ),
    ]
    .iter()
    .map(|(name, desc, _)| {
        ListItem::new(Line::from(vec![
            Span::styled(" ○ ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                *name,
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" — ", Style::new().fg(Color::DarkGray)),
            Span::styled(*desc, Style::new().fg(Color::White)),
        ]))
    })
    .collect();

    let module_list = List::new(module_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Available Scanner Modules ")
            .border_style(Style::new().fg(Color::Cyan)),
    );
    frame.render_widget(module_list, module_area);
}

fn render_findings(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
    if app.findings.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No findings yet. Run a scan from the Scanner tab.",
            Style::new().fg(Color::DarkGray),
        )))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Findings Explorer ")
                .border_style(Style::new().fg(Color::Cyan)),
        );
        frame.render_widget(empty, area);
        return;
    }

    let chunks = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
        .areas::<2>(area);

    let [list_area, detail_area] = chunks;
    app.findings_list_area = Some(list_area);

    let items: Vec<ListItem> = app
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
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
                Span::styled(
                    format!("{} ", confidence_icon),
                    Style::new().fg(severity_color),
                ),
                Span::styled(
                    format!("{:?} ", f.severity),
                    Style::new().fg(severity_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(&f.title, Style::new().fg(Color::White)),
            ]))
        })
        .collect();

    let selected_style = Style::new()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);
    let findings_list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Findings List ")
                .border_style(Style::new().fg(Color::Cyan)),
        )
        .highlight_style(selected_style)
        .highlight_symbol("> ");

    frame.render_stateful_widget(
        findings_list,
        list_area,
        &mut ratatui::widgets::ListState::default().with_selected(app.selected_finding),
    );

    if let Some(idx) = app.selected_finding
        && let Some(finding) = app.findings.get(idx)
    {
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
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Finding Details ")
                    .border_style(Style::new().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(detail_widget, detail_area);
    }
}

fn render_payloads(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
    let chunks = Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)])
        .areas::<2>(area);

    let [list_area, detail_area] = chunks;
    app.payload_set_list_area = Some(list_area);

    // Left: payload set list.
    let set_items: Vec<ListItem> = app
        .payload_sets
        .iter()
        .enumerate()
        .map(|(i, set)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:>2} ", i + 1), Style::new().fg(Color::DarkGray)),
                Span::styled(
                    set.id.clone(),
                    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" ({})", set.payloads.len()),
                    Style::new().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let set_list = List::new(set_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Payload Sets ")
                .border_style(Style::new().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::new()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(
        set_list,
        list_area,
        &mut ratatui::widgets::ListState::default().with_selected(Some(app.selected_payload_set)),
    );

    // Right: the selected set's payloads.
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::Yellow));

    if let Some(set) = app.current_payload_set() {
        let detail = detail_block.title(Span::styled(
            format!(" {} ", set.title),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));

        let mut lines: Vec<Line> = vec![
            Line::from(Span::styled(
                "When to use: ",
                Style::new().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                set.when_to_use.clone(),
                Style::new().fg(Color::White),
            )),
            Line::from(""),
        ];

        for payload in &set.payloads {
            lines.push(Line::from(vec![
                Span::styled(
                    "▸ ",
                    Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    payload.value.clone(),
                    Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
            ]));
            let mut meta = format!(
                "   {} — difficulty {}/5",
                payload.description, payload.difficulty
            );
            if !payload.tag.is_empty() {
                meta = format!("{} [{}]", meta, payload.tag);
            }
            lines.push(Line::from(Span::styled(
                meta,
                Style::new().fg(Color::DarkGray),
            )));
        }

        let paragraph = Paragraph::new(Text::from(lines))
            .block(detail)
            .wrap(Wrap { trim: false })
            .scroll((app.payload_scroll, 0));
        frame.render_widget(paragraph, detail_area);
    } else {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No payload set selected.",
            Style::new().fg(Color::DarkGray),
        )))
        .block(detail_block.title(" Payloads "));
        frame.render_widget(empty, detail_area);
    }
}

fn render_plan(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
    let plan = &app.plan;
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Target: ", Style::new().fg(Color::DarkGray)),
        Span::styled(
            plan.target.clone(),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
    ]));
    if !plan.engagement_id.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Engagement: ", Style::new().fg(Color::DarkGray)),
            Span::styled(plan.engagement_id.clone(), Style::new().fg(Color::White)),
        ]));
    }
    lines.push(Line::from(""));

    for step in &plan.steps {
        let weight_color = match step.weight {
            4..=5 => Color::Red,
            3 => Color::Yellow,
            _ => Color::Green,
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>2}. ", step.order),
                Style::new().fg(Color::DarkGray),
            ),
            Span::styled(
                step.action.clone(),
                Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  [{}/5]", step.weight),
                Style::new().fg(weight_color),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("    {}", step.rationale),
            Style::new().fg(Color::Gray),
        )));
    }

    if !plan.suggested_payload_sets.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Suggested payload sets (see Payloads tab):",
            Style::new().fg(Color::Yellow),
        )));
        for id in &plan.suggested_payload_sets {
            lines.push(Line::from(Span::styled(
                format!("  • {}", id),
                Style::new().fg(Color::Magenta),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("Methodology checklist: {}", plan.checklist_id),
        Style::new().fg(Color::DarkGray),
    )));

    let widget = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    " Engagement Plan ",
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                ))
                .border_style(Style::new().fg(Color::Green)),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.plan_scroll, 0));
    frame.render_widget(widget, area);
}

fn render_logs(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
    if app.logs.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No log entries yet.",
            Style::new().fg(Color::DarkGray),
        )))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Live Log Stream ")
                .border_style(Style::new().fg(Color::Cyan)),
        );
        frame.render_widget(empty, area);
        return;
    }

    let log_items: Vec<ListItem> = app
        .logs
        .iter()
        .rev()
        .skip(app.log_scroll)
        .take(50)
        .map(|entry| {
            let level_color = match entry.level.as_str() {
                "ERROR" => Color::Red,
                "WARN" => Color::Yellow,
                "INFO" => Color::Green,
                "DEBUG" => Color::Blue,
                _ => Color::White,
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", entry.timestamp),
                    Style::new().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("[{:<5}] ", entry.level),
                    Style::new().fg(level_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<20} ", entry.module),
                    Style::new().fg(Color::Cyan),
                ),
                Span::styled(&entry.message, Style::new().fg(Color::White)),
            ]))
        })
        .collect();

    let log_list = List::new(log_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Live Log Stream ")
            .border_style(Style::new().fg(Color::Cyan)),
    );
    frame.render_widget(log_list, area);
}

fn render_config(frame: &mut Frame, area: Rect, app: &mut GrymTuiApp) {
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
    let tier_widget = Paragraph::new(tier_info).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Technique Tiers ")
            .border_style(Style::new().fg(Color::Yellow)),
    );
    frame.render_widget(tier_widget, tier_area);

    let deepness_info = "\
Deepness Profiles:
  Quick    — Low-noise, short inventory pass
  Standard — Balanced default
  Deep     — Broader coverage, no risky validation
  Paranoid — Lowest-noise, highest-review profile";
    let deepness_widget = Paragraph::new(deepness_info).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Deepness Profiles ")
            .border_style(Style::new().fg(Color::Cyan)),
    );
    frame.render_widget(deepness_widget, deepness_area);

    let limits_info = format!(
        "Limits & Safety:\n  Global Rate: 20 req/s | Per-Host: 3 req/s | Max Redirects: 5\n  Block Threshold: 60% | 5xx Threshold: 5\n  Findings: {} total ({} high, {} med, {} low, {} info)",
        app.metrics.findings_count,
        app.metrics.high_severity,
        app.metrics.medium_severity,
        app.metrics.low_severity,
        app.metrics.info_count,
    );
    let limits_widget = Paragraph::new(limits_info).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Limits & Safety ")
            .border_style(Style::new().fg(Color::Green)),
    );
    frame.render_widget(limits_widget, limits_area);
}

const HELP_CONTENT: &[&str] = &[
    "GRYM TUI — Help & Controls",
    "",
    "NAVIGATION CONTROLS",
    "  [1] Dashboard  [2] Scanner  [3] Findings  [4] Payloads",
    "  [5] Plan       [6] Logs      [7] Config",
    "  [Tab] / [Shift+Tab] — Next / previous tab",
    "  [←] / [→]           — Switch tabs (same as Tab/Shift+Tab)",
    "  [↑] / [↓] or [k] / [j] — Move selection up / down",
    "  [PageUp] / [PageDown] — Fast scroll in Logs / Help",
    "  [Home] / [End]      — Jump to top / bottom of Help",
    "  [Enter]             — View selected finding details",
    "",
    "MOUSE CONTROLS",
    "  • Click a tab in the header bar to switch tabs instantly.",
    "  • Click a payload set in the Payloads list to view its payloads.",
    "  • Click a finding in the Findings list to select it.",
    "  • Scroll wheel (or trackpad) scrolls Logs, Payloads, and Findings lists.",
    "  • Click the [h] Help button in the footer to open this help screen.",
    "  • Click anywhere inside the help screen, or the Close button, to close it.",
    "",
    "USAGE CONTROLS",
    "  • Dashboard: live status, request counts, blocked requests, elapsed time.",
    "  • Scanner: review available modules. From the CLI use 'grym scan <target>'",
    "            or launch the web dashboard/API to start real scans.",
    "  • Findings: browse, select, and inspect every discovered issue.",
    "  • Payloads: curated payload library with when-to-use guidance. Select a",
    "            set on the left; copy payloads manually into your own tooling.",
    "  • Plan: auto-generated engagement plan from your scope.toml settings —",
    "            ordered steps, time weights, and suggested payload sets.",
    "  • Logs: real-time stream from all modules. Scroll with wheel/Page keys.",
    "  • Config: current technique tiers and deepness profiles.",
    "",
    "TAB DESCRIPTIONS",
    "  1 Dashboard — Overview, scan status, severity counts, active modules.",
    "  2 Scanner   — Available modules: DNS enum, port scan, web crawler, tech",
    "              fingerprint, vulnerability scan, and CVE correlation.",
    "  3 Findings  — List + detail pane for all discovered vulnerabilities.",
    "  4 Payloads  — Reference payload sets (SQLi, XSS, SSTI, NoSQLi, SSRF,",
    "              XXE, traversal, redirect) with context and difficulty.",
    "  5 Plan      — Engagement plan: ordered methodology steps sized to your",
    "              scope tier/deepness, plus suggested payload sets.",
    "  6 Logs      — Live log stream from scanner, transport, and core modules.",
    "  7 Config    — Technique tiers (Passive -> Active Validation) and safety",
    "              limits (rate limits, redirect depth, block thresholds).",
    "",
    "SAFETY & SCOPE",
    "  GRYM will refuse to send any traffic unless a valid scope.toml is loaded.",
    "  Keep scope limited, authorized, and time-bound. Never point at systems you",
    "  do not own or have explicit written permission to test.",
    "",
    "ACTIONS",
    "  [h]        — Toggle this help screen",
    "  [q] / [Esc] — Quit the TUI (or close this help screen)",
];

fn render_help_overlay(frame: &mut Frame, app: &mut GrymTuiApp) {
    let area = frame.area();
    let popup = centered_rect(85, 85, area);

    // Clear the background so the popup stands out.
    frame.render_widget(Clear, popup);

    let inner = popup.inner(ratatui::layout::Margin {
        horizontal: 1,
        vertical: 1,
    });
    let button_height = 1u16;
    let content_height = inner.height.saturating_sub(button_height + 1);
    let [content_area, button_area] = Layout::vertical([
        Constraint::Length(content_height),
        Constraint::Length(button_height),
    ])
    .areas::<2>(inner);

    let lines: Vec<Line> = HELP_CONTENT
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let style = if i == 0 {
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else if line.starts_with("NAVIGATION")
                || line.starts_with("MOUSE")
                || line.starts_with("USAGE")
                || line.starts_with("TAB")
                || line.starts_with("SAFETY")
                || line.starts_with("ACTIONS")
            {
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else if line.starts_with("  •") || line.starts_with("  [") {
                Style::new().fg(Color::White)
            } else {
                Style::new().fg(Color::Gray)
            };
            Line::from(Span::styled(*line, style))
        })
        .collect();

    let help_text = Text::from(lines);
    let help_paragraph = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::NONE))
        .scroll((app.help_scroll as u16, 0));
    frame.render_widget(help_paragraph, content_area);

    // Render a clickable Close button in the bottom-right of the popup.
    let close_label = " [ Close ] ";
    let close_width = close_label.len() as u16;
    let close_x = button_area.x + button_area.width.saturating_sub(close_width + 2);
    let close_rect = Rect {
        x: close_x,
        y: button_area.y,
        width: close_width,
        height: 1,
    };
    let close = Paragraph::new(close_label).style(
        Style::new()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(close, close_rect);
    app.help_close_area = Some(close_rect);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_width = area.width * percent_x / 100;
    let popup_height = area.height * percent_y / 100;
    let x = area.width.saturating_sub(popup_width) / 2;
    let y = area.height.saturating_sub(popup_height) / 2;
    Rect {
        x: area.x + x,
        y: area.y + y,
        width: popup_width,
        height: popup_height,
    }
}
