//! Workspace maintenance commands that do not contact assessment targets.

#![deny(unsafe_code)]

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

/// Development automation for GRYM maintainers.
#[derive(Debug, Parser)]
#[command(name = "cargo xtask")]
struct Xtask {
    /// Maintenance operation.
    #[command(subcommand)]
    command: Command,
}

/// Available offline maintenance operations.
#[derive(Debug, Subcommand)]
enum Command {
    /// Ensure every mapping pack is parseable YAML and declares a version.
    MappingCheck,
}

fn main() -> Result<()> {
    match Xtask::parse().command {
        Command::MappingCheck => mapping_check(Path::new("mapping-packs")),
    }
}

fn mapping_check(directory: &Path) -> Result<()> {
    let mut checked = 0_u32;
    for entry in fs::read_dir(directory).context("unable to enumerate mapping-packs")? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "yaml" || extension == "yml")
        {
            let content = fs::read_to_string(&path)?;
            let value = serde_yaml::from_str::<serde_yaml::Value>(&content)
                .with_context(|| format!("invalid YAML in {}", path.display()))?;
            if value.get("version").is_none() {
                bail!("mapping pack {} does not declare version", path.display());
            }
            checked = checked.saturating_add(1);
        }
    }
    if checked == 0 {
        bail!("no mapping packs found in {}", directory.display());
    }
    println!("validated {checked} mapping pack(s)");
    Ok(())
}
