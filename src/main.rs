mod ci;
mod config;
mod lockfile;
mod mise;
mod platform;
mod registry;
mod source;
mod tool;
mod verify;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "kit",
    version,
    about = "Verified tool registry manager",
    long_about = "kit manages developer toolchains from git-based registries.\n\n\
        Tools are defined in per-tool TOML files within registries. kit resolves versions\n\
        across multiple registries, generates mise configuration, verifies checksums and\n\
        signatures, and automates upstream update tracking.\n\n\
        Supply chain CI (three-pipeline architecture):\n  \
        kit sense                     # Pipeline 1: detect upstream changes\n  \
        kit evaluate + kit apply      # Pipeline 2: LLM assessment + MR\n  \
        kit verify-registry           # Pipeline 3: validate before merge\n\n\
        User commands:\n  \
        kit setup                     # one-time: create config, add registry\n  \
        kit sync                      # pull registries, generate mise config, verify\n  \
        kit status                    # show installed vs registry, drift detection\n  \
        kit verify                    # re-verify all installed binaries\n  \
        kit add gh cli/cli            # add a tool from GitHub\n  \
        kit pin gh 2.73.0             # pin a version locally\n  \
        kit init --ci                 # create a new registry with CI automation"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// One-time setup: create config, optionally add a registry
    Setup {
        /// Registry URL to add (e.g., https://gitlab.com/nomograph/kits.git)
        #[arg(long)]
        registry: Option<String>,
        /// Name for the registry (defaults to inferring from URL)
        #[arg(long)]
        name: Option<String>,
    },

    /// Pull registries, resolve versions, generate mise config, verify
    Sync {
        /// Accept all changes without confirmation
        #[arg(long)]
        yes: bool,
    },

    /// Show installed vs registry, drift detection
    Status,

    /// Re-verify all installed binaries from scratch
    Verify,

    /// Add a tool to a writable registry
    Add {
        /// Tool name
        name: String,
        /// Source (owner/repo for GitHub/GitLab, package name for npm/crates)
        source: Option<String>,
        /// GitLab project (source is the repo path, e.g. nomograph/muxr)
        #[arg(long)]
        gitlab: bool,
        /// npm package
        #[arg(long)]
        npm: bool,
        /// Crates.io package
        #[arg(long)]
        crates: bool,
    },

    /// Push a tool definition to its registry
    Push {
        /// Tool name
        name: String,
    },

    /// Remove a tool from a writable registry
    Remove {
        /// Tool name
        name: String,
    },

    /// Pin a tool's version or registry source locally
    Pin {
        /// Tool name
        name: String,
        /// Version to pin (omit for registry-only pin)
        version: Option<String>,
        /// Pin to specific registry
        #[arg(long, short)]
        registry: Option<String>,
    },

    /// Remove a local pin
    Unpin {
        /// Tool name
        name: String,
    },

    /// Check upstream for newer versions (CI mode)
    Check {
        /// Registry directory to check
        #[arg(long)]
        registry: Option<PathBuf>,
        /// Output file for update candidates
        #[arg(long, default_value = "updates.json")]
        output: PathBuf,
    },

    /// LLM evaluation of edge-case updates (CI mode)
    Evaluate {
        /// Input file from check phase
        #[arg(long, default_value = "updates.json")]
        input: PathBuf,
        /// Output file for evaluation results
        #[arg(long, default_value = "evaluated.json")]
        output: PathBuf,
    },

    /// Apply evaluated updates to registry, create MR (CI mode)
    Apply {
        /// Input file from evaluate phase
        #[arg(long, default_value = "evaluated.json")]
        input: PathBuf,
    },

    /// Detect upstream changes (Pipeline 1: Sense)
    ///
    /// Scans all tools in a registry for upstream updates, downloads and verifies
    /// checksums, queries advisory databases, and produces a classified report.
    /// Always succeeds unless infrastructure is broken (network, auth).
    Sense {
        /// Registry directory to scan
        #[arg(long)]
        registry: Option<PathBuf>,
        /// Output file for the sense report
        #[arg(long, default_value = "sense-report.json")]
        output: PathBuf,
    },

    /// Validate all tool definitions in a registry (Pipeline 3: Verify)
    ///
    /// Loads every TOML file in tools/, validates fields and checksums,
    /// and re-verifies checksums against upstream where possible.
    /// Used in MR pipelines as the deterministic gate before merge.
    VerifyRegistry {
        /// Registry directory to validate
        #[arg(long)]
        registry: Option<PathBuf>,
        /// Output file for verification results
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Check installed tools for known security advisories
    Audit,

    /// Initialize a new registry
    Init {
        /// Include CI automation template
        #[arg(long)]
        ci: bool,
        /// Registry name
        #[arg(long, default_value = "my-registry")]
        name: String,
    },

    /// Show changes between local lockfile and current registry
    Diff,

    /// Check upstream for updates and apply interactively
    Upgrade {
        /// Apply all available updates without prompting
        #[arg(long)]
        yes: bool,
        /// Only check a specific tool
        tool: Option<String>,
    },

    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell to generate for
        shell: clap_complete::Shell,
    },

    /// Generate man page
    #[command(hide = true)]
    ManPage,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup { registry, name } => cmd_setup(registry.as_deref(), name.as_deref()),
        Commands::Sync { yes } => cmd_sync(yes),
        Commands::Status => cmd_status(),
        Commands::Verify => cmd_verify(),
        Commands::Add {
            name,
            source,
            gitlab,
            npm,
            crates,
        } => cmd_add(&name, source.as_deref(), gitlab, npm, crates),

        Commands::Push { name } => cmd_push(&name),
        Commands::Remove { name } => cmd_remove(&name),
        Commands::Pin {
            name,
            version,
            registry,
        } => cmd_pin(&name, version.as_deref(), registry.as_deref()),
        Commands::Unpin { name } => cmd_unpin(&name),
        Commands::Audit => cmd_audit(),
        Commands::Diff => cmd_diff(),
        Commands::Check { registry, output } => cmd_check(registry.as_deref(), &output),
        Commands::Evaluate { input, output } => cmd_evaluate(&input, &output),
        Commands::Apply { input } => cmd_apply(&input),
        Commands::Sense { registry, output } => cmd_sense(registry.as_deref(), &output),
        Commands::VerifyRegistry { registry, output } => {
            cmd_verify_registry(registry.as_deref(), output.as_deref())
        }
        Commands::Init { ci, name } => cmd_init(ci, &name),
        Commands::Upgrade { yes, tool } => cmd_upgrade(yes, tool.as_deref()),
        Commands::Completions { shell } => cmd_completions(shell),
        Commands::ManPage => cmd_man_page(),
    }
}

fn cmd_completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "kit", &mut std::io::stdout());
    Ok(())
}

fn cmd_man_page() -> Result<()> {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    man.render(&mut std::io::stdout())
        .context("failed to render man page")?;
    Ok(())
}

fn cmd_diff() -> Result<()> {
    let config = config::Config::load()?;

    // Pull registries to get latest definitions
    for reg in &config.registry {
        match registry::ensure_registry(&config, reg) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("  warning: could not pull registry {}: {e}", reg.name);
            }
        }
    }

    // Resolve tools from registries
    let mut resolved = registry::resolve_tools(&config)?;
    registry::apply_pins(&mut resolved, &config.pins, &config)?;

    // Load lockfile
    let lock = lockfile::Lockfile::load(&config)?;

    if lock.entries.is_empty() {
        eprintln!("No lockfile found. Run `kit sync` first.");
        return Ok(());
    }

    // Build the new-resolved tuples for lockfile::diff
    let new_resolved: Vec<(String, String, String)> = resolved
        .iter()
        .map(|rt| {
            (
                rt.def.name.clone(),
                rt.def.version.clone(),
                rt.registry.clone(),
            )
        })
        .collect();

    let changes = lockfile::diff(&lock, &new_resolved);

    if changes.is_empty() {
        eprintln!("kit diff: no changes ({} tools unchanged)", resolved.len());
        return Ok(());
    }

    // Print table header
    let mut changed_count = 0;
    eprintln!();
    eprintln!(
        "  {:<20} {:<12} {:<12} CHANGE",
        "TOOL", "LOCKFILE", "REGISTRY"
    );
    for change in &changes {
        match change {
            lockfile::Change::Updated {
                name, from, to, ..
            } => {
                let bump = detect_bump(from, to);
                eprintln!(
                    "  {:<20} {:<12} {:<12} {} bump",
                    name, from, to, bump
                );
                changed_count += 1;
            }
            lockfile::Change::Added { name } => {
                // Find the version from resolved
                let version = resolved
                    .iter()
                    .find(|rt| rt.def.name == *name)
                    .map(|rt| rt.def.version.as_str())
                    .unwrap_or("?");
                eprintln!(
                    "  {:<20} {:<12} {:<12} new",
                    name, "--", version
                );
                changed_count += 1;
            }
            lockfile::Change::Removed { name } => {
                let version = lock
                    .get(name)
                    .map(|e| e.version.as_str())
                    .unwrap_or("?");
                eprintln!(
                    "  {:<20} {:<12} {:<12} removed",
                    name, version, "--"
                );
                changed_count += 1;
            }
            lockfile::Change::RegistryMoved {
                name, from, to, ..
            } => {
                let version = lock
                    .get(name)
                    .map(|e| e.version.as_str())
                    .unwrap_or("?");
                eprintln!(
                    "  {:<20} {:<12} {:<12} registry: {} -> {}",
                    name, version, version, from, to
                );
                changed_count += 1;
            }
        }
    }

    let unchanged = resolved.len().saturating_sub(changed_count);
    if unchanged > 0 {
        eprintln!("  ({} tools unchanged)", unchanged);
    }
    eprintln!();

    Ok(())
}

fn cmd_upgrade(auto_yes: bool, tool_filter: Option<&str>) -> Result<()> {
    let config = config::Config::load()?;

    // Pull registries to ensure we have latest definitions
    for reg in &config.registry {
        match registry::ensure_registry(&config, reg) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("  warning: could not pull registry {}: {e}", reg.name);
            }
        }
    }

    let mut resolved = registry::resolve_tools(&config)?;
    registry::apply_pins(&mut resolved, &config.pins, &config)?;

    // Filter to the specific tool if requested
    if let Some(name) = tool_filter {
        resolved.retain(|rt| rt.def.name == name);
        if resolved.is_empty() {
            anyhow::bail!("tool '{name}' not found in any registry");
        }
    }

    eprintln!("kit upgrade: checking {} tools for updates\n", resolved.len());

    struct UpgradeCandidate {
        name: String,
        current: String,
        available: String,
        bump: String,
        registry_dir: PathBuf,
    }

    let mut candidates: Vec<UpgradeCandidate> = Vec::new();

    for rt in &resolved {
        eprint!("  {:<20} ", rt.def.name);

        // Skip sources we can't auto-check
        match rt.def.source {
            tool::Source::Direct => {
                eprintln!("{:<12} skip (direct source)", rt.def.version);
                continue;
            }
            tool::Source::Rustup => {
                eprintln!("{:<12} skip (rustup)", rt.def.version);
                continue;
            }
            tool::Source::Npm => {
                eprintln!("{:<12} skip (npm)", rt.def.version);
                continue;
            }
            tool::Source::Crates => {
                eprintln!("{:<12} skip (crates)", rt.def.version);
                continue;
            }
            _ => {}
        }

        let upstream = match rt.def.source {
            tool::Source::Github => {
                let repo = match rt.def.repo.as_deref() {
                    Some(r) => r,
                    None => {
                        eprintln!("{:<12} skip (no repo)", rt.def.version);
                        continue;
                    }
                };
                source::query_github(repo)
            }
            tool::Source::Gitlab => {
                let repo = match rt.def.repo.as_deref() {
                    Some(r) => r,
                    None => {
                        eprintln!("{:<12} skip (no repo)", rt.def.version);
                        continue;
                    }
                };
                source::query_gitlab(repo)
            }
            _ => unreachable!(),
        };

        match upstream {
            Ok(info) => {
                if info.version == rt.def.version {
                    eprintln!("{:<12} up to date", rt.def.version);
                } else {
                    let bump = detect_bump(&rt.def.version, &info.version);
                    eprintln!(
                        "{:<12} -> {:<12} ({})",
                        rt.def.version, info.version, bump
                    );
                    let registry_dir = config.registry_dir()?.join(&rt.registry);
                    candidates.push(UpgradeCandidate {
                        name: rt.def.name.clone(),
                        current: rt.def.version.clone(),
                        available: info.version,
                        bump,
                        registry_dir,
                    });
                }
            }
            Err(e) => {
                eprintln!("{:<12} error ({e:#})", rt.def.version);
            }
        }
    }

    if candidates.is_empty() {
        eprintln!("\nAll tools are up to date.");
        return Ok(());
    }

    // Print summary table
    eprintln!();
    eprintln!(
        "  {:<20} {:<12} {:<12} BUMP",
        "TOOL", "CURRENT", "AVAILABLE"
    );
    for c in &candidates {
        eprintln!(
            "  {:<20} {:<12} {:<12} {}",
            c.name, c.current, c.available, c.bump
        );
    }
    eprintln!();

    // Confirm or auto-apply
    let proceed = if auto_yes {
        true
    } else {
        eprint!("Apply {} update(s)? [y/N] ", candidates.len());
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap_or(0);
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    };

    if !proceed {
        eprintln!("Aborted.");
        return Ok(());
    }

    // Apply updates to TOML files
    for c in &candidates {
        let tool_path = c.registry_dir.join("tools").join(format!("{}.toml", c.name));
        if !tool_path.exists() {
            eprintln!("  warning: {}.toml not found, skipping", c.name);
            continue;
        }

        let raw = std::fs::read_to_string(&tool_path)
            .with_context(|| format!("failed to read {}", tool_path.display()))?;

        let mut doc = raw
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("failed to parse {} as TOML", tool_path.display()))?;

        if let Some(tool_table) = doc.get_mut("tool").and_then(|t| t.as_table_mut()) {
            tool_table["version"] = toml_edit::value(c.available.as_str());
            // Remove stale checksums -- they belong to the old version.
            tool_table.remove("checksums");
        } else {
            eprintln!("  warning: no [tool] table in {}.toml, skipping", c.name);
            continue;
        }

        std::fs::write(&tool_path, doc.to_string())
            .with_context(|| format!("failed to write {}", tool_path.display()))?;

        eprintln!("  updated {}: {} -> {}", c.name, c.current, c.available);
    }

    eprintln!("\nRun `kit sync` to install the updates.");
    Ok(())
}

/// Compare semver components to determine the bump type.
/// Returns true if `to` is an older version than `from` by simple numeric comparison.
fn is_version_downgrade(from: &str, to: &str) -> bool {
    let parse = |v: &str| -> (u64, u64, u64) {
        let parts: Vec<&str> = v.split('.').collect();
        let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let patch = parts
            .get(2)
            .and_then(|p| p.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        (major, minor, patch)
    };
    parse(to) < parse(from)
}

fn detect_bump(current: &str, available: &str) -> String {
    let parse = |v: &str| -> (u64, u64, u64) {
        let parts: Vec<&str> = v.split('.').collect();
        let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        // Strip any pre-release suffix from the patch component (e.g. "0-beta.1" -> 0)
        let patch = parts
            .get(2)
            .and_then(|p| p.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        (major, minor, patch)
    };

    let (cm, cmi, _cp) = parse(current);
    let (am, ami, _ap) = parse(available);

    if am != cm {
        "major".to_string()
    } else if ami != cmi {
        "minor".to_string()
    } else {
        "patch".to_string()
    }
}

fn cmd_setup(registry_url: Option<&str>, registry_name: Option<&str>) -> Result<()> {
    let config_path = config::Config::path()?;
    if config_path.exists() {
        // If --registry was passed, add it to the existing config rather than erroring.
        if let Some(url) = registry_url {
            let mut config = config::Config::load()?;
            let name = registry_name.unwrap_or_else(|| {
                url.trim_end_matches(".git")
                    .rsplit('/')
                    .next()
                    .unwrap_or("default")
            });
            if config.registry(name).is_some() {
                eprintln!("Registry '{name}' already configured.");
                return Ok(());
            }
            config.registry.push(config::Registry {
                name: name.to_string(),
                url: url.to_string(),
                branch: "main".to_string(),
                readonly: false,
            });
            config.save()?;
            eprintln!("Added registry '{name}' to {}", config_path.display());
            eprintln!("Run `kit sync` to pull tools and generate mise config.");
            return Ok(());
        }
        eprintln!("Config already exists at {}", config_path.display());
        eprintln!("To add a registry: kit setup --registry <url>");
        return Ok(());
    }

    let config = if let Some(url) = registry_url {
        // Infer registry name from URL if not provided
        let name = registry_name.unwrap_or_else(|| {
            url.trim_end_matches(".git")
                .rsplit('/')
                .next()
                .unwrap_or("default")
        });
        config::Config::default_with_registry(name, url)
    } else {
        // No default registry -- user adds their own
        config::Config {
            settings: config::Settings::default(),
            registry: vec![],
            pins: std::collections::HashMap::new(),
        }
    };
    config.save()?;
    eprintln!("Created {}", config_path.display());
    if registry_url.is_some() {
        eprintln!("Run `kit sync` to pull tools and generate mise config.");
    } else {
        eprintln!("No registry configured. Add one to your config:");
        eprintln!("  [[registry]]");
        eprintln!("  name = \"my-registry\"");
        eprintln!("  url = \"https://gitlab.com/your/registry.git\"");
        eprintln!("\nOr run: kit setup --registry https://gitlab.com/your/registry.git");
    }
    eprintln!();
    eprintln!("Tip: enable shell completions:");
    eprintln!("  kit completions zsh > ~/.zfunc/_kit    # zsh");
    eprintln!("  kit completions bash > /etc/bash_completion.d/kit  # bash");
    Ok(())
}

fn cmd_sync(auto_yes: bool) -> Result<()> {
    let config = config::Config::load()?;
    let platform = resolve_platform(&config)?;

    eprintln!("kit sync ({})", platform);

    // 1. Pull all registries
    for reg in &config.registry {
        eprint!("  pulling {}... ", reg.name);
        match registry::ensure_registry(&config, reg) {
            Ok(_) => eprintln!("ok"),
            Err(e) => {
                eprintln!("FAILED: {e}");
                eprintln!("  skipping registry {}", reg.name);
            }
        }
    }

    // 2. Resolve tools across registries
    let mut resolved = registry::resolve_tools(&config)?;
    registry::apply_pins(&mut resolved, &config.pins, &config)?;
    eprintln!("  resolved {} tools", resolved.len());

    // 3. Resolve expected checksums for ALL tools (inline + checksum files).
    // This must happen before generating mise config so that a tampered
    // checksum is caught before any binaries are downloaded.
    let mut registry_checksums: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    let tools_with_checksums: Vec<&registry::ResolvedTool> = resolved
        .iter()
        .filter(|rt| {
            rt.def.checksums.contains_key(platform.key())
                || rt.def.checksum.is_some()
        })
        .collect();
    if !tools_with_checksums.is_empty() {
        eprintln!("  resolving checksums for {} tools...", tools_with_checksums.len());
    }
    for rt in &tools_with_checksums {
        // Inline checksums are immediate; checksum files require HTTP.
        if let Some(inline) = rt.def.checksums.get(platform.key()) {
            registry_checksums.insert(rt.def.name.clone(), Some(inline.clone()));
        } else {
            // Download the checksum file for this tool+platform.
            match verify::resolve_expected_checksum(&rt.def, platform) {
                Ok(verify::VerifyResult::Verified { sha256, .. }) => {
                    eprintln!("    {} checksum resolved", rt.def.name);
                    registry_checksums.insert(rt.def.name.clone(), Some(sha256));
                }
                Ok(verify::VerifyResult::Failed { reason, .. }) => {
                    eprintln!("    {} checksum FAILED: {}", rt.def.name, reason);
                    registry_checksums.insert(rt.def.name.clone(), None);
                }
                Ok(verify::VerifyResult::Unavailable { reason }) => {
                    eprintln!("    {} checksum unavailable: {}", rt.def.name, reason);
                    registry_checksums.insert(rt.def.name.clone(), None);
                }
                Err(e) => {
                    eprintln!("    {} checksum error: {:#}", rt.def.name, e);
                    registry_checksums.insert(rt.def.name.clone(), None);
                }
            }
        }
    }

    // 4. Load existing lockfile and check integrity
    let old_lock = lockfile::Lockfile::load(&config)?;

    // S-2: ALWAYS check integrity, even when diff shows no version changes.
    // A compromised registry could change only the checksum (same version).
    // This check must run unconditionally -- it is the primary supply chain defense.
    // Uses resolved checksums (inline + downloaded) so ALL tools are covered.
    for rt in &resolved {
        let sha = registry_checksums
            .get(&rt.def.name)
            .and_then(|opt| opt.as_deref());
        let result = old_lock.check_integrity(
            &rt.def.name,
            &rt.def.version,
            sha,
        );
        if result == lockfile::IntegrityResult::ChecksumChanged {
            anyhow::bail!(
                "SUPPLY CHAIN ALERT: {} has same version but different checksum. \
                 This may indicate a compromised upstream release. Aborting.",
                rt.def.name
            );
        }
    }

    // Build the new-resolved tuples for diff
    let new_tuples: Vec<(String, String, String)> = resolved
        .iter()
        .map(|rt| (rt.def.name.clone(), rt.def.version.clone(), rt.registry.clone()))
        .collect();
    let changes = lockfile::diff(&old_lock, &new_tuples);

    if !changes.is_empty() {
        eprintln!("\n  Changes:");
        for change in &changes {
            eprintln!("    {change}");
        }

        // Warn explicitly on version downgrades (registry pins an older version
        // than what the user already has installed).
        let downgrades: Vec<(&str, &str, &str)> = changes
            .iter()
            .filter_map(|c| {
                if let lockfile::Change::Updated { name, from, to } = c {
                    if is_version_downgrade(from, to) {
                        Some((name.as_str(), from.as_str(), to.as_str()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        if !downgrades.is_empty() {
            eprintln!("\n  WARNING: the following tools would be downgraded:");
            for (name, from, to) in &downgrades {
                eprintln!("    {name}: {from} -> {to}  (downgrade)");
            }
            if !auto_yes {
                eprintln!("  Use --yes to accept version downgrades.");
                anyhow::bail!("version downgrades detected -- review and re-run with --yes");
            }
        }

        // S-9: registry migration requires confirmation
        let has_registry_moves = changes
            .iter()
            .any(|c| matches!(c, lockfile::Change::RegistryMoved { .. }));

        if has_registry_moves && !auto_yes {
            eprintln!("\n  Tools have moved between registries. Use --yes to accept.");
            anyhow::bail!("registry migration detected -- review and re-run with --yes");
        }
    } else {
        eprintln!("  no changes");
    }

    // 5. Generate mise config (S-3: uses toml crate, not string interpolation)
    let mise_content = mise::generate(&resolved, &config)?;
    let mise_path = config.mise_config_path()?;
    if let Some(parent) = mise_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&mise_path, &mise_content)?;
    eprintln!("  wrote {}", mise_path.display());

    // 6. Run mise install
    eprint!("  running mise install... ");
    let mise_ok = match std::process::Command::new("mise")
        .args(["install", "--yes"])
        .status()
    {
        Ok(s) if s.success() => {
            eprintln!("ok");
            true
        }
        Ok(s) => {
            eprintln!("warning: mise install exited {s}");
            false
        }
        Err(e) => {
            eprintln!("warning: could not run mise: {e}");
            false
        }
    };

    // F12: warn clearly if mise failed -- lockfile will still be updated
    // but the `installed` field will reflect the failure.
    if !mise_ok {
        eprintln!("  warning: lockfile updated but mise install failed -- tools may not be installed");
    }

    // 7. Update lockfile
    // T3-1: store registry checksums and binary checksums separately.
    // Registry checksums (inline + downloaded) are used by S-2 integrity checks.
    // Binary checksums (F6) are computed from installed binaries.
    let mise_installs = dirs::home_dir()
        .unwrap_or_default()
        .join(".local/share/mise/installs");

    let mut new_lock = lockfile::Lockfile {
        entries: std::collections::HashMap::new(),
    };
    for rt in &resolved {
        let url = rt.def.url_for(platform).unwrap_or_default();
        // Registry checksum (inline or downloaded) -- for S-2 comparison
        let registry_sha = registry_checksums
            .get(&rt.def.name)
            .and_then(|opt| opt.as_deref());
        // F6: compute actual binary checksum from installed location
        let binary_sha = if mise_ok {
            resolve_installed_sha(&rt.def, platform, &mise_installs)
        } else {
            None
        };
        let method = verification_method(&rt.def);

        new_lock.set(
            &rt.def.name,
            lockfile::new_entry(
                &rt.def.version,
                &rt.registry,
                if url.is_empty() { None } else { Some(url.as_str()) },
                registry_sha,
                binary_sha.as_deref(),
                method,
            ),
        );
    }
    new_lock.save(&config)?;

    eprintln!("\n  {} tools synced.", resolved.len());
    Ok(())
}

fn cmd_status() -> Result<()> {
    let config = config::Config::load()?;

    let mut resolved = registry::resolve_tools(&config)?;
    registry::apply_pins(&mut resolved, &config.pins, &config)?;
    let lock = lockfile::Lockfile::load(&config)?;

    println!(
        "  {:<20} {:<12} {:<10} {:<10} {:<10} {:<12}",
        "TOOL", "VERSION", "STATUS", "REGISTRY", "TIER", "VERIFY"
    );

    for rt in &resolved {
        let (status, verify_method) = match lock.get(&rt.def.name) {
            Some(entry) => {
                let s = if entry.version == rt.def.version {
                    "current"
                } else {
                    "outdated"
                };
                (s, entry.verification_method.as_str())
            }
            None => ("new", ""),
        };

        let pinned = if config.pins.contains_key(&rt.def.name) {
            " (pinned)"
        } else {
            ""
        };

        println!(
            "  {:<20} {:<12} {:<10} {:<10} {:<10} {verify_method}{pinned}",
            rt.def.name, rt.def.version, status, rt.registry, rt.def.tier
        );
    }

    Ok(())
}

fn cmd_verify() -> Result<()> {
    let config = config::Config::load()?;
    let platform = resolve_platform(&config)?;

    let mut resolved = registry::resolve_tools(&config)?;
    registry::apply_pins(&mut resolved, &config.pins, &config)?;

    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut skip = 0u32;

    for rt in &resolved {
        eprint!("  {:<20} {:<12} ", rt.def.name, rt.def.version);

        // Tools installed via package managers (npm, crates, rustup) don't have
        // download URLs for checksum verification -- skip them early.
        if matches!(
            rt.def.source,
            tool::Source::Npm | tool::Source::Crates | tool::Source::Rustup
        ) {
            eprintln!("skip  (package-manager install, no binary checksum)");
            skip += 1;
            continue;
        }

        // Resolve the binary path via `mise which`.
        let binary_path = match verify::resolve_binary_path(&rt.def) {
            Some(p) => p,
            None => {
                eprintln!("skip  (binary not found via mise)");
                skip += 1;
                continue;
            }
        };

        match verify::verify_tool(&rt.def, platform, &binary_path) {
            Ok(verify::VerifyResult::Verified { method, .. }) => {
                eprintln!("ok  ({method})");
                pass += 1;
            }
            Ok(verify::VerifyResult::Failed { method, reason }) => {
                eprintln!("FAIL  ({method}: {reason})");
                fail += 1;
            }
            Ok(verify::VerifyResult::Unavailable { reason }) => {
                eprintln!("skip  ({reason})");
                skip += 1;
            }
            Err(e) => {
                eprintln!("error  ({e})");
                skip += 1;
            }
        }
    }

    eprintln!("\n  {pass} verified, {fail} failed, {skip} skipped");
    if fail > 0 {
        anyhow::bail!("{fail} tools failed verification");
    }
    Ok(())
}

fn cmd_add(name: &str, source: Option<&str>, gitlab: bool, npm: bool, crates: bool) -> Result<()> {
    tool::validate_name(name)?;
    let config = config::Config::load()?;

    let reg = config
        .registry
        .iter()
        .find(|r| !r.readonly)
        .ok_or_else(|| anyhow::anyhow!("no writable registry configured"))?;

    let registry_dir = config.registry_dir()?.join(&reg.name);
    let tools_dir = registry_dir.join("tools");
    let tool_path = tools_dir.join(format!("{name}.toml"));

    if tool_path.exists() {
        anyhow::bail!("{name} already exists in registry {}", reg.name);
    }

    let (source_type, repo, pkg, crate_name) = if crates {
        (tool::Source::Crates, None, None, source.map(|s| s.to_string()))
    } else if npm {
        (tool::Source::Npm, None, source.map(|s| s.to_string()), None)
    } else if gitlab {
        (tool::Source::Gitlab, source.map(|s| s.to_string()), None, None)
    } else {
        (tool::Source::Github, source.map(|s| s.to_string()), None, None)
    };

    // Query upstream for version, assets, and checksum info.
    let upstream = match source_type {
        tool::Source::Github => {
            let repo_str = source
                .ok_or_else(|| anyhow::anyhow!("GitHub source requires owner/repo argument"))?;
            eprint!("  querying GitHub {repo_str}... ");
            match source::query_github(repo_str) {
                Ok(info) => {
                    eprintln!("ok ({})", info.version);
                    Some(info)
                }
                Err(e) => {
                    eprintln!("failed ({e:#})");
                    eprintln!("  falling back to skeleton definition");
                    None
                }
            }
        }
        tool::Source::Gitlab => {
            let repo_str = source.ok_or_else(|| {
                anyhow::anyhow!("GitLab source requires owner/repo path argument")
            })?;
            eprint!("  querying GitLab {repo_str}... ");
            match source::query_gitlab(repo_str) {
                Ok(info) => {
                    eprintln!(
                        "ok ({}, project_id={})",
                        info.version,
                        info.project_id.unwrap_or(0)
                    );
                    Some(info)
                }
                Err(e) => {
                    eprintln!("failed ({e:#})");
                    eprintln!("  falling back to skeleton definition");
                    None
                }
            }
        }
        tool::Source::Npm => {
            let pkg_name = source.unwrap_or(name);
            eprint!("  querying npm {pkg_name}... ");
            match source::query_npm(pkg_name) {
                Ok(info) => {
                    eprintln!("ok ({})", info.version);
                    Some(info)
                }
                Err(e) => {
                    eprintln!("failed ({e:#})");
                    eprintln!("  falling back to skeleton definition");
                    None
                }
            }
        }
        tool::Source::Crates => {
            let crate_str = source.unwrap_or(name);
            eprint!("  querying crates.io {crate_str}... ");
            match source::query_crates(crate_str) {
                Ok(info) => {
                    eprintln!("ok ({})", info.version);
                    Some(info)
                }
                Err(e) => {
                    eprintln!("failed ({e:#})");
                    eprintln!("  falling back to skeleton definition");
                    None
                }
            }
        }
        _ => None,
    };

    // Detect aqua registry membership for GitHub tools.
    let aqua = if source_type == tool::Source::Github {
        eprint!("  detecting aqua registry... ");
        match source::detect_aqua(name, source) {
            Some(id) => {
                eprintln!("found ({id})");
                Some(id)
            }
            None => {
                eprintln!("not found");
                None
            }
        }
    } else {
        None
    };

    // Determine tier: "own" if the tool's namespace matches the registry namespace.
    let resolved_project_id = upstream.as_ref().and_then(|u| u.project_id);
    let tier = detect_tier(gitlab, source, &reg.url, &registry_dir);

    // Build the tool definition, populated from upstream when available.
    let (version, tag_prefix, assets, checksum) = match &upstream {
        Some(info) => {
            let templated_assets = source::templatize_assets(&info.assets, &info.version);
            let checksum_cfg = info.checksum_file.as_ref().map(|f| tool::ChecksumConfig {
                file: Some(source::templatize_checksum(f, &info.version)),
                format: info
                    .checksum_format
                    .clone()
                    .unwrap_or(tool::ChecksumFormat::Sha256),
            });
            (
                info.version.clone(),
                info.tag_prefix.clone(),
                templated_assets,
                checksum_cfg,
            )
        }
        None => (
            "0.0.0".to_string(),
            "v".to_string(),
            std::collections::HashMap::new(),
            None,
        ),
    };

    // Auto-detect cosign signature config from upstream.
    let signature = upstream
        .as_ref()
        .and_then(|info| info.signature_method.as_ref())
        .map(|method| match method.as_str() {
            "cosign-keyless" if gitlab => {
                let repo_path = source.unwrap_or("");
                tool::SignatureConfig {
                    method: tool::SignatureMethod::CosignKeyless,
                    issuer: Some("https://gitlab.com".to_string()),
                    identity: Some(format!("https://gitlab.com/{repo_path}")),
                }
            }
            "cosign-keyless" => tool::SignatureConfig {
                method: tool::SignatureMethod::CosignKeyless,
                issuer: None,
                identity: None,
            },
            _ => tool::SignatureConfig {
                method: tool::SignatureMethod::None,
                issuer: None,
                identity: None,
            },
        });

    let file = tool::ToolFile {
        tool: tool::ToolDef {
            name: name.to_string(),
            description: None,
            source: source_type,
            version,
            tag_prefix,
            bin: Some(name.to_string()),
            tier,
            repo: repo.clone(),
            project_id: resolved_project_id,
            package: pkg,
            crate_name,
            aqua,
            assets,
            checksum,
            checksums: std::collections::HashMap::new(),
            signature,
        },
    };

    let content = format!(
        "# Tool definition for {name}\n\
         # Review the detected values, then `kit push {name}`\n\n\
         {}",
        toml::to_string_pretty(&file)?
    );

    std::fs::create_dir_all(&tools_dir)?;
    std::fs::write(&tool_path, content)?;

    eprintln!("\nCreated {}", tool_path.display());

    // Print what was detected for user verification.
    if let Some(info) = &upstream {
        eprintln!("\n  Detected from upstream:");
        eprintln!("    version:     {}", info.version);
        eprintln!("    tag_prefix:  {:?}", info.tag_prefix);
        if let Some(pid) = info.project_id {
            eprintln!("    project_id:  {pid}");
        }
        if let Some(a) = info.assets.get("macos-arm64") {
            eprintln!("    macos-arm64: {a}");
        }
        if let Some(a) = info.assets.get("linux-x64") {
            eprintln!("    linux-x64:   {a}");
        }
        if let Some(f) = &info.checksum_file {
            eprintln!("    checksum:    {f}");
        }
        if let Some(m) = &info.signature_method {
            eprintln!("    signature:   {m}");
        }
        let missing: Vec<&str> = ["macos-arm64", "linux-x64"]
            .iter()
            .filter(|p| !info.assets.contains_key(**p))
            .copied()
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "    warning: no assets detected for: {}",
                missing.join(", ")
            );
        }
    }
    eprintln!("    tier:        {tier}");
    if let Some(ref a) = file.tool.aqua {
        eprintln!("    aqua:        {a}");
    }

    eprintln!("\nReview the definition, then run `kit push {name}`");
    Ok(())
}

/// Detect tier based on whether the tool's source namespace matches the registry namespace.
fn detect_tier(
    gitlab: bool,
    source: Option<&str>,
    registry_url: &str,
    registry_dir: &std::path::Path,
) -> tool::Tier {
    // Try to get the namespace from _meta.toml, falling back to URL extraction.
    let registry_ns = tool::load_registry_meta(registry_dir)
        .ok()
        .and_then(|meta| {
            // Use the maintainer field if set, otherwise the registry name.
            meta.registry.maintainer.or(Some(meta.registry.name))
        });

    // Fall back to extracting namespace from the registry URL.
    let url_ns = source::extract_registry_namespace(registry_url);
    let effective_ns = registry_ns.or(url_ns);

    if let (Some(ns), Some(src)) = (effective_ns, source)
        && let Some(src_ns) = src.split('/').next()
        && src_ns == ns
    {
        return if gitlab {
            // GitLab tools from the same org are "own" -- you control the release pipeline.
            tool::Tier::Own
        } else {
            // GitHub tools from the same org are "high" trust.
            tool::Tier::High
        };
    }

    tool::Tier::Low
}

fn cmd_push(name: &str) -> Result<()> {
    tool::validate_name(name)?;
    let config = config::Config::load()?;

    let reg = config
        .registry
        .iter()
        .find(|r| !r.readonly)
        .ok_or_else(|| anyhow::anyhow!("no writable registry configured"))?;

    let registry_dir = config.registry_dir()?.join(&reg.name);
    let tool_path = registry_dir.join("tools").join(format!("{name}.toml"));

    if !tool_path.exists() {
        anyhow::bail!("{name}.toml not found in registry {}", reg.name);
    }

    // Validate before pushing
    let _def = tool::ToolDef::load(&tool_path)?;

    // Git add + commit via CLI
    let relative = std::path::Path::new("tools").join(format!("{name}.toml"));
    let add_status = std::process::Command::new("git")
        .args(["add", &relative.to_string_lossy()])
        .current_dir(&registry_dir)
        .status()
        .context("failed to run git add")?;
    if !add_status.success() {
        anyhow::bail!("git add failed for {name}.toml");
    }

    let message = format!("kit: add {name}");
    let commit_status = std::process::Command::new("git")
        .args(["commit", "-m", &message])
        .current_dir(&registry_dir)
        .status()
        .context("failed to run git commit")?;
    if !commit_status.success() {
        anyhow::bail!("git commit failed for {name}.toml");
    }

    // Push via git CLI (needs system credential helpers)
    let status = std::process::Command::new("git")
        .args(["push", "--quiet", "origin", &reg.branch])
        .current_dir(&registry_dir)
        .status()
        .context("failed to run git push")?;

    if !status.success() {
        anyhow::bail!("git push failed for registry {}", reg.name);
    }

    eprintln!("Pushed {name} to {}", reg.name);
    Ok(())
}

fn cmd_remove(name: &str) -> Result<()> {
    tool::validate_name(name)?;
    let config = config::Config::load()?;

    let reg = config
        .registry
        .iter()
        .find(|r| !r.readonly)
        .ok_or_else(|| anyhow::anyhow!("no writable registry configured"))?;

    let registry_dir = config.registry_dir()?.join(&reg.name);
    let tool_path = registry_dir.join("tools").join(format!("{name}.toml"));

    if !tool_path.exists() {
        anyhow::bail!("{name}.toml not found in registry {}", reg.name);
    }

    std::fs::remove_file(&tool_path)
        .with_context(|| format!("failed to delete {}", tool_path.display()))?;

    // Git add + commit + push (same pattern as cmd_push)
    let relative = std::path::Path::new("tools").join(format!("{name}.toml"));
    let add_status = std::process::Command::new("git")
        .args(["add", &relative.to_string_lossy()])
        .current_dir(&registry_dir)
        .status()
        .context("failed to run git add")?;
    if !add_status.success() {
        anyhow::bail!("git add failed for {name}.toml");
    }

    let message = format!("kit: remove {name}");
    let commit_status = std::process::Command::new("git")
        .args(["commit", "-m", &message])
        .current_dir(&registry_dir)
        .status()
        .context("failed to run git commit")?;
    if !commit_status.success() {
        anyhow::bail!("git commit failed for {name}.toml");
    }

    let status = std::process::Command::new("git")
        .args(["push", "--quiet", "origin", &reg.branch])
        .current_dir(&registry_dir)
        .status()
        .context("failed to run git push")?;

    if !status.success() {
        anyhow::bail!("git push failed for registry {}", reg.name);
    }

    eprintln!("Removed {name} from {}", reg.name);
    Ok(())
}

fn cmd_audit() -> Result<()> {
    let config = config::Config::load()?;

    let mut resolved = registry::resolve_tools(&config)?;
    registry::apply_pins(&mut resolved, &config.pins, &config)?;

    eprintln!("kit audit: checking {} tools for security advisories\n", resolved.len());

    let mut findings: Vec<(String, String, ci::Advisory)> = Vec::new();

    for rt in &resolved {
        eprint!("  {:<20} {:<12} ", rt.def.name, rt.def.version);

        let advs = match rt.def.source {
            tool::Source::Github => audit_github(&rt.def),
            tool::Source::Npm => audit_npm(&rt.def),
            _ => {
                eprintln!("skip (no advisory source for {:?})", rt.def.source);
                continue;
            }
        };

        match advs {
            Ok(ref list) if list.is_empty() => {
                eprintln!("ok");
            }
            Ok(list) => {
                eprintln!("{} advisory(ies)", list.len());
                for a in list {
                    findings.push((rt.def.name.clone(), rt.def.version.clone(), a));
                }
            }
            Err(e) => {
                eprintln!("error ({e:#})");
            }
        }
    }

    if findings.is_empty() {
        eprintln!("\nNo advisories found.");
        return Ok(());
    }

    eprintln!("\n{}", "=".repeat(80));
    eprintln!(
        "  {:<20} {:<12} {:<20} {:<12} SUMMARY",
        "TOOL", "VERSION", "CVE", "SEVERITY"
    );
    eprintln!("{}", "-".repeat(80));
    for (tool_name, version, adv) in &findings {
        let summary = &adv.summary;
        eprintln!(
            "  {tool_name:<20} {version:<12} {:<20} {:<12} {summary}",
            adv.id, adv.severity
        );
    }
    eprintln!("{}", "=".repeat(80));
    eprintln!("{} advisory(ies) found.", findings.len());

    let has_critical = findings
        .iter()
        .any(|(_, _, a)| a.severity == "high" || a.severity == "critical");

    if has_critical {
        anyhow::bail!("high or critical advisories found -- action required");
    }

    Ok(())
}

/// Query GitHub Advisory Database for a GitHub-sourced tool.
fn audit_github(def: &tool::ToolDef) -> Result<Vec<ci::Advisory>> {
    let repo = def
        .repo
        .as_deref()
        .context("github source requires 'repo' field")?;

    let escaped_version = def.version.replace('.', "\\\\.");
    let jq_filter = format!(
        r#"[.[] | select(.vulnerabilities[]?.vulnerable_version_range | test("{escaped_version}"))]"#
    );

    let output = std::process::Command::new("gh")
        .args([
            "api",
            &format!("repos/{repo}/security-advisories"),
            "--jq",
            &jq_filter,
        ])
        .output()
        .context("failed to execute gh")?;

    if !output.status.success() {
        // Some repos have no advisories endpoint -- not an error
        return Ok(vec![]);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "[]" || trimmed == "null" {
        return Ok(vec![]);
    }

    let raw: Vec<serde_json::Value> = serde_json::from_str(trimmed).unwrap_or_default();

    Ok(raw
        .iter()
        .map(|a| ci::Advisory {
            id: a["ghsa_id"].as_str().unwrap_or("?").to_string(),
            severity: a["severity"].as_str().unwrap_or("?").to_string(),
            summary: a["summary"]
                .as_str()
                .unwrap_or("?")
                .chars()
                .take(200)
                .collect(),
        })
        .collect())
}

/// Query GitHub Advisory Database for an npm package.
fn audit_npm(def: &tool::ToolDef) -> Result<Vec<ci::Advisory>> {
    let pkg = def.package.as_deref().unwrap_or(&def.name);
    let version = &def.version;

    let output = std::process::Command::new("gh")
        .args([
            "api",
            &format!(
                "/advisories?ecosystem=npm&package={pkg}&affects={version}"
            ),
        ])
        .output()
        .context("failed to execute gh")?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "[]" || trimmed == "null" {
        return Ok(vec![]);
    }

    let raw: Vec<serde_json::Value> = serde_json::from_str(trimmed).unwrap_or_default();

    Ok(raw
        .iter()
        .map(|a| ci::Advisory {
            id: a["ghsa_id"]
                .as_str()
                .or_else(|| a["cve_id"].as_str())
                .unwrap_or("?")
                .to_string(),
            severity: a["severity"].as_str().unwrap_or("?").to_string(),
            summary: a["summary"]
                .as_str()
                .unwrap_or("?")
                .chars()
                .take(200)
                .collect(),
        })
        .collect())
}

fn cmd_pin(name: &str, version: Option<&str>, registry: Option<&str>) -> Result<()> {
    if let Some(v) = version {
        tool::validate_version(v)
            .with_context(|| format!("invalid pin version for '{name}'"))?;
    }

    let mut config = config::Config::load()?;

    let pin = config::Pin {
        version: version.map(|s| s.to_string()),
        registry: registry.map(|s| s.to_string()),
    };

    config.pins.insert(name.to_string(), pin);
    config.save()?;

    match (version, registry) {
        (Some(v), Some(r)) => eprintln!("Pinned {name} to {v} from {r}"),
        (Some(v), None) => eprintln!("Pinned {name} to {v}"),
        (None, Some(r)) => eprintln!("Pinned {name} to registry {r}"),
        (None, None) => eprintln!("Pin created for {name} (no version or registry specified)"),
    }

    eprintln!("Run `kit sync` to apply.");
    Ok(())
}

fn cmd_unpin(name: &str) -> Result<()> {
    let mut config = config::Config::load()?;

    if config.pins.remove(name).is_some() {
        config.save()?;
        eprintln!("Unpinned {name}. Run `kit sync` to apply.");
    } else {
        eprintln!("{name} is not pinned.");
    }

    Ok(())
}

fn cmd_check(registry: Option<&std::path::Path>, output: &std::path::Path) -> Result<()> {
    let registry_dir = registry
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    ci::check(&registry_dir, output)
}

fn cmd_evaluate(input: &std::path::Path, output: &std::path::Path) -> Result<()> {
    ci::evaluate(input, output)
}

fn cmd_apply(input: &std::path::Path) -> Result<()> {
    ci::apply(input)
}

fn cmd_sense(registry: Option<&std::path::Path>, output: &std::path::Path) -> Result<()> {
    let registry_dir = registry
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    ci::sense(&registry_dir, output)
}

fn cmd_verify_registry(
    registry: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
) -> Result<()> {
    let registry_dir = registry
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    ci::verify_registry(&registry_dir, output)
}

fn cmd_init(ci: bool, name: &str) -> Result<()> {
    tool::validate_name(name)
        .context("invalid registry name (must be lowercase alphanumeric + hyphens)")?;
    let tools_dir = std::path::Path::new("tools");
    if tools_dir.exists() {
        anyhow::bail!("tools/ directory already exists");
    }

    std::fs::create_dir_all(tools_dir)?;

    let meta = format!(
        "[registry]\nname = \"{name}\"\ndescription = \"\"\nmaintainer = \"\"\n\n\
         [policy]\nauto_merge_tiers = [\"low\"]\n\
         auto_merge_bump = [\"patch\", \"minor\"]\n\
         auto_merge_requires_checksum = true\n"
    );
    std::fs::write(tools_dir.join("_meta.toml"), meta)?;
    eprintln!("Created tools/_meta.toml");

    std::fs::write(
        ".gitignore",
        "updates.json\nupdates.json.sha256\nevaluated.json\nevaluated.json.sha256\nsense-report.json\nsense-report.json.sha256\n__pycache__/\n",
    )?;

    if ci {
        std::fs::write(".gitlab-ci.yml", CI_TEMPLATE)?;
        eprintln!("Created .gitlab-ci.yml");
    }

    eprintln!("Registry initialized. Add tools with `kit add <name> <source>`.");
    Ok(())
}

// -- Helpers --

fn resolve_platform(config: &config::Config) -> Result<platform::Platform> {
    match &config.settings.platform {
        Some(p) => platform::Platform::from_key(p)
            .ok_or_else(|| anyhow::anyhow!("unknown platform: {p}")),
        None => platform::Platform::detect(),
    }
}

fn verification_method(def: &tool::ToolDef) -> &'static str {
    match &def.signature {
        Some(sig) => match sig.method {
            tool::SignatureMethod::CosignKeyless => "cosign",
            tool::SignatureMethod::GithubAttestation => "attestation",
            tool::SignatureMethod::None => has_checksum(def),
        },
        None => has_checksum(def),
    }
}

fn has_checksum(def: &tool::ToolDef) -> &'static str {
    if def.checksum.is_some() || !def.checksums.is_empty() {
        "checksum"
    } else {
        "none"
    }
}

/// F6: compute the actual SHA256 of an installed binary.
/// Returns None if the binary isn't found (not installed or different layout).
fn resolve_installed_sha(
    def: &tool::ToolDef,
    _platform: platform::Platform,
    _mise_installs: &std::path::Path,
) -> Option<String> {
    // Use `mise which` for authoritative binary resolution.
    if let Some(bin_path) = verify::resolve_binary_path(def) {
        return verify::compute_sha256(&bin_path).ok();
    }

    // Binary not found -- return None rather than falling back to registry
    // checksums, which are expected values not actual installed hashes.
    None
}

const CI_TEMPLATE: &str = r#"# kit registry CI -- three-pipeline supply chain architecture
#
# Pipeline 1: Sense   (scheduled) -- detect upstream changes, produce report
# Pipeline 2: Respond (scheduled) -- LLM assessment, open MR with audit trail
# Pipeline 3: Verify  (MR)        -- independent validation, gate before merge

stages:
  - sense
  - respond
  - verify

variables:
  CLAUDE_MODEL: "claude-haiku-4-5-20251001"

# ---------------------------------------------------------------------------
# Pipeline 1: Sense (scheduled -- detect upstream changes)
# ---------------------------------------------------------------------------
# NEVER fails on version drift (that is what it is designed to detect).
# ONLY fails on infrastructure issues (cannot reach upstream, auth failure).

kit:sense:
  stage: sense
  image: rust:1.93-bookworm
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
  before_script:
    - cargo install --locked nomograph-kit || true
  script:
    - kit sense --registry . --output sense-report.json
    - sha256sum sense-report.json > sense-report.json.sha256
  artifacts:
    paths: [sense-report.json, sense-report.json.sha256]
    expire_in: 1 day

# ---------------------------------------------------------------------------
# Pipeline 2: Respond (triggered after sense -- LLM assessment + MR)
# ---------------------------------------------------------------------------
# Reads the sense report, classifies each finding, opens an MR with the
# full audit trail as the description.

kit:evaluate:
  stage: respond
  image: rust:1.93-bookworm
  needs: [kit:sense]
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
  before_script:
    - cargo install --locked nomograph-kit || true
  script:
    - sha256sum -c sense-report.json.sha256
    - kit evaluate --input sense-report.json --output evaluated.json
    - sha256sum evaluated.json > evaluated.json.sha256
  artifacts:
    paths: [evaluated.json, evaluated.json.sha256]
    expire_in: 1 day

kit:apply:
  stage: respond
  image: rust:1.93-bookworm
  needs: [kit:evaluate]
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
  before_script:
    - cargo install --locked nomograph-kit || true
    - apt-get update -qq && apt-get install -y -qq git > /dev/null
    - git config user.email "kit-bot@localhost"
    - git config user.name "kit"
  script:
    - sha256sum -c evaluated.json.sha256
    - kit apply --input evaluated.json

# ---------------------------------------------------------------------------
# Pipeline 3: Verify (triggered by MR -- independent validation)
# ---------------------------------------------------------------------------
# Validates all tool definitions, re-verifies checksums independently.
# If all pass, MR is ready for merge.

kit:verify:
  stage: verify
  image: rust:1.93-bookworm
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  before_script:
    - cargo install --locked nomograph-kit || true
  script:
    - kit verify-registry --registry .
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_bump_major() {
        assert_eq!(detect_bump("2.5.0", "3.0.6"), "major");
        assert_eq!(detect_bump("1.0.0", "2.0.0"), "major");
    }

    #[test]
    fn detect_bump_minor() {
        assert_eq!(detect_bump("1.85.0", "1.86.0"), "minor");
        assert_eq!(detect_bump("1.56.0", "1.91.0"), "minor");
    }

    #[test]
    fn detect_bump_patch() {
        assert_eq!(detect_bump("2.5.0", "2.5.1"), "patch");
        assert_eq!(detect_bump("1.0.0", "1.0.3"), "patch");
    }

    #[test]
    fn detect_bump_prerelease() {
        assert_eq!(detect_bump("1.0.0-beta.1", "1.0.0"), "patch");
        assert_eq!(detect_bump("1.0.0", "2.0.0-rc.1"), "major");
    }
}
