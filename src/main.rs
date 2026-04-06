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
        Example:\n  \
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
    /// One-time setup: create config, add first registry, initial sync
    Setup,

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
        /// Source (owner/repo for GitHub, --gitlab for GitLab, --npm for npm)
        source: Option<String>,
        /// GitLab project (use with --gitlab)
        #[arg(long)]
        gitlab: bool,
        /// GitLab project ID (for own tools)
        #[arg(long)]
        project_id: Option<u64>,
        /// npm package
        #[arg(long)]
        npm: bool,
    },

    /// Push a tool definition to its registry
    Push {
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

    /// Initialize a new registry
    Init {
        /// Include CI automation template
        #[arg(long)]
        ci: bool,
        /// Registry name
        #[arg(long, default_value = "my-registry")]
        name: String,
    },

    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell to generate for
        shell: clap_complete::Shell,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => cmd_setup(),
        Commands::Sync { yes } => cmd_sync(yes),
        Commands::Status => cmd_status(),
        Commands::Verify => cmd_verify(),
        Commands::Add {
            name,
            source,
            gitlab,
            project_id,
            npm,
        } => cmd_add(&name, source.as_deref(), gitlab, project_id, npm),
        Commands::Push { name } => cmd_push(&name),
        Commands::Pin {
            name,
            version,
            registry,
        } => cmd_pin(&name, version.as_deref(), registry.as_deref()),
        Commands::Unpin { name } => cmd_unpin(&name),
        Commands::Check { registry, output } => cmd_check(registry.as_deref(), &output),
        Commands::Evaluate { input, output } => cmd_evaluate(&input, &output),
        Commands::Apply { input } => cmd_apply(&input),
        Commands::Init { ci, name } => cmd_init(ci, &name),
        Commands::Completions { shell } => cmd_completions(shell),
    }
}

fn cmd_completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "kit", &mut std::io::stdout());
    Ok(())
}

fn cmd_setup() -> Result<()> {
    let config_path = config::Config::path()?;
    if config_path.exists() {
        eprintln!("Config already exists at {}", config_path.display());
        eprintln!("Edit it directly or delete it to re-run setup.");
        return Ok(());
    }

    let config = config::Config::default_with_registry(
        "dunn",
        "https://gitlab.com/nomograph/kits.git",
    );
    config.save()?;
    eprintln!("Created {}", config_path.display());
    eprintln!("Run `kit sync` to pull tools and generate mise config.");
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

    // 3. Load existing lockfile and check integrity
    let old_lock = lockfile::Lockfile::load(&config)?;

    // S-2: ALWAYS check integrity, even when diff shows no version changes.
    // A compromised registry could change only the checksum (same version).
    // This check must run unconditionally -- it is the primary supply chain defense.
    for rt in &resolved {
        let sha = rt.def.checksums.get(platform.key());
        let result = old_lock.check_integrity(
            &rt.def.name,
            &rt.def.version,
            sha.map(|s| s.as_str()),
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

    // 4. Generate mise config (S-3: uses toml crate, not string interpolation)
    let mise_content = mise::generate(&resolved, &config)?;
    let mise_path = config.mise_config_path()?;
    if let Some(parent) = mise_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&mise_path, &mise_content)?;
    eprintln!("  wrote {}", mise_path.display());

    // 5. Run mise install
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

    // 6. Update lockfile
    // T3-1: store registry checksums and binary checksums separately.
    // Registry checksums (archive hashes) are used by S-2 integrity checks.
    // Binary checksums (F6) are computed from installed binaries.
    let mise_installs = dirs::home_dir()
        .unwrap_or_default()
        .join(".local/share/mise/installs");

    let mut new_lock = lockfile::Lockfile {
        entries: std::collections::HashMap::new(),
    };
    for rt in &resolved {
        let url = rt.def.url_for(platform).unwrap_or_default();
        // Registry inline checksum (archive hash) -- for S-2 comparison
        let registry_sha = rt.def.checksums.get(platform.key()).map(|s| s.as_str());
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
        "  {:<20} {:<12} {:<10} {:<10} {:<10}",
        "TOOL", "VERSION", "STATUS", "REGISTRY", "TIER"
    );

    for rt in &resolved {
        let status = match lock.get(&rt.def.name) {
            Some(entry) => {
                if entry.version == rt.def.version {
                    "current"
                } else {
                    "outdated"
                }
            }
            None => "new",
        };

        let pinned = if config.pins.contains_key(&rt.def.name) {
            " (pinned)"
        } else {
            ""
        };

        println!(
            "  {:<20} {:<12} {:<10} {:<10} {}{pinned}",
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
        // Resolve mise install dir for this tool
        let mise_dir = dirs::home_dir()
            .unwrap_or_default()
            .join(".local/share/mise/installs");
        // mise installs http: backends under http-<name>/<version>
        let tool_install_dir = match rt.def.source {
            tool::Source::Npm => mise_dir.join(format!("npm-{}", rt.def.package.as_deref().unwrap_or(&rt.def.name).replace('/', "-").replace('@', ""))).join(&rt.def.version),
            tool::Source::Rustup => mise_dir.join("rust").join(&rt.def.version),
            _ => {
                if rt.def.aqua.is_some() {
                    mise_dir.join(&rt.def.name).join(&rt.def.version)
                } else {
                    mise_dir.join(format!("http-{}", rt.def.name)).join(&rt.def.version)
                }
            }
        };
        match verify::verify_tool(&rt.def, platform, &tool_install_dir) {
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

fn cmd_add(
    name: &str,
    source: Option<&str>,
    gitlab: bool,
    project_id: Option<u64>,
    npm: bool,
) -> Result<()> {
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

    let (source_type, repo, pkg) = if npm {
        (tool::Source::Npm, None, source.map(|s| s.to_string()))
    } else if gitlab {
        (tool::Source::Gitlab, source.map(|s| s.to_string()), None)
    } else {
        (tool::Source::Github, source.map(|s| s.to_string()), None)
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
            let repo_str = source.unwrap_or("");
            eprint!("  querying GitLab... ");
            match source::query_gitlab(repo_str, project_id) {
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
        _ => None,
    };

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

    let file = tool::ToolFile {
        tool: tool::ToolDef {
            name: name.to_string(),
            description: None,
            source: source_type,
            version,
            tag_prefix,
            bin: Some(name.to_string()),
            tier: tool::Tier::Low,
            repo: repo.clone(),
            project_id,
            package: pkg,
            crate_name: None,
            aqua: None,
            assets,
            checksum,
            checksums: std::collections::HashMap::new(),
            signature: None,
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
        if let Some(a) = info.assets.get("macos-arm64") {
            eprintln!("    macos-arm64: {a}");
        }
        if let Some(a) = info.assets.get("linux-x64") {
            eprintln!("    linux-x64:   {a}");
        }
        if let Some(f) = &info.checksum_file {
            eprintln!("    checksum:    {f}");
        }
        let missing: Vec<&str> = ["macos-arm64", "linux-x64"]
            .iter()
            .filter(|p| !info.assets.contains_key(**p))
            .copied()
            .collect();
        if !missing.is_empty() {
            eprintln!("    warning: no assets detected for: {}", missing.join(", "));
        }
    }

    eprintln!("\nReview the definition, then run `kit push {name}`");
    Ok(())
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

fn cmd_pin(name: &str, version: Option<&str>, registry: Option<&str>) -> Result<()> {
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
        "updates.json\nupdates.json.sha256\nevaluated.json\nevaluated.json.sha256\n__pycache__/\n",
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
    platform: platform::Platform,
    mise_installs: &std::path::Path,
) -> Option<String> {
    let install_dir = match def.source {
        tool::Source::Npm => {
            let pkg = def.package.as_deref().unwrap_or(&def.name).replace('/', "-").replace('@', "");
            mise_installs.join(format!("npm-{pkg}")).join(&def.version)
        }
        tool::Source::Rustup => mise_installs.join("rust").join(&def.version),
        _ => {
            if def.aqua.is_some() {
                mise_installs.join(&def.name).join(&def.version)
            } else {
                mise_installs.join(format!("http-{}", def.name)).join(&def.version)
            }
        }
    };

    let bin_path = install_dir.join("bin").join(def.bin_name());
    if bin_path.exists() {
        verify::compute_sha256(&bin_path).ok()
    } else {
        // Some mise backends put the binary directly in the version dir
        let alt_path = install_dir.join(def.bin_name());
        if alt_path.exists() {
            verify::compute_sha256(&alt_path).ok()
        } else {
            // Fall back to inline checksums from registry
            def.checksums.get(platform.key()).cloned()
        }
    }
}

const CI_TEMPLATE: &str = r#"# kit registry CI automation
stages:
  - check
  - evaluate
  - apply

variables:
  CLAUDE_MODEL: "claude-haiku-4-5-20251001"

kit:check:
  stage: check
  image: rust:1.93-bookworm
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
  before_script:
    - cargo install --locked kit || true
  script:
    - kit check --registry . --output updates.json
    - sha256sum updates.json > updates.json.sha256
  artifacts:
    paths: [updates.json, updates.json.sha256]
    expire_in: 1 day

kit:evaluate:
  stage: evaluate
  image: rust:1.93-bookworm
  needs: [kit:check]
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
  before_script:
    - cargo install --locked kit || true
  script:
    - sha256sum -c updates.json.sha256
    - kit evaluate --input updates.json --output evaluated.json
    - sha256sum evaluated.json > evaluated.json.sha256
  artifacts:
    paths: [evaluated.json, evaluated.json.sha256]
    expire_in: 1 day

kit:apply:
  stage: apply
  image: rust:1.93-bookworm
  needs: [kit:evaluate]
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
  before_script:
    - cargo install --locked kit || true
    - apt-get update -qq && apt-get install -y -qq git > /dev/null
    - git config user.email "kit-bot@localhost"
    - git config user.name "kit"
  script:
    - sha256sum -c evaluated.json.sha256
    - kit apply --input evaluated.json
"#;
