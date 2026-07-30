#![deny(unsafe_code)]

pub mod app;
pub mod ui;
pub mod widgets;

pub use app::GrymTuiApp;

use anyhow::Result;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;

pub async fn run() -> Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = GrymTuiApp::new();
    let result = app.run(&mut terminal).await;

    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;

    result
}
