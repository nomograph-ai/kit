use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::{Config, Pin, Registry};
use crate::tool::{load_registry_tools, ToolDef};

/// A tool definition resolved to its source registry.
#[derive(Debug, Clone)]
pub struct ResolvedTool {
    pub def: ToolDef,
    pub registry: String,
}

// -- Git operations (shell out to git for credential helper support) --

/// Clone a registry with shallow depth.
fn clone(url: &str, dest: &Path, branch: &str) -> Result<()> {
    let status = std::process::Command::new("git")
        .args([
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--branch",
            branch,
            "--single-branch",
            url,
        ])
        .arg(dest)
        .status()
        .context("Failed to run git clone")?;
    if !status.success() {
        anyhow::bail!("git clone failed for {url}");
    }
    Ok(())
}

/// Fast-forward pull an existing clone.
fn pull(repo_dir: &Path, branch: &str) -> Result<()> {
    let status = std::process::Command::new("git")
        .args(["pull", "--quiet", "--ff-only", "origin", branch])
        .current_dir(repo_dir)
        .status()
        .context("Failed to run git pull")?;
    if !status.success() {
        anyhow::bail!("git pull failed in {}", repo_dir.display());
    }
    Ok(())
}

// -- Public API --

/// Ensure a registry is cloned and up to date. Returns the local path.
///
/// Clones the registry if it doesn't exist locally, otherwise pulls the
/// latest changes. Uses `--depth 1 --single-branch` for clones and
/// `--ff-only` for pulls to keep the local copy minimal and safe.
pub fn ensure_registry(config: &Config, reg: &Registry) -> Result<PathBuf> {
    let registry_dir = config.registry_dir()?;
    std::fs::create_dir_all(&registry_dir)
        .with_context(|| format!("failed to create {}", registry_dir.display()))?;

    let dest = registry_dir.join(&reg.name);

    if dest.join(".git").exists() {
        // F19: if --ff-only pull fails (e.g. force-pushed remote), re-clone from scratch
        if let Err(e) = pull(&dest, &reg.branch) {
            eprintln!("  pull failed ({e:#}), re-cloning from scratch");
            std::fs::remove_dir_all(&dest)
                .with_context(|| format!("failed to remove {}", dest.display()))?;
            clone(&reg.url, &dest, &reg.branch)
                .with_context(|| format!("failed to re-clone registry '{}'", reg.name))?;
        }
    } else {
        // Remove the directory if it exists but isn't a valid git repo
        // (e.g. partial clone that was interrupted).
        if dest.exists() {
            std::fs::remove_dir_all(&dest).with_context(|| {
                format!(
                    "failed to remove stale directory {}",
                    dest.display()
                )
            })?;
        }
        eprintln!("  cloning {}", reg.name);
        clone(&reg.url, &dest, &reg.branch)
            .with_context(|| format!("failed to clone registry '{}'", reg.name))?;
    }

    Ok(dest)
}

/// Resolve tools across all registries in priority order.
///
/// Registries are iterated in the order they appear in the config (index 0
/// is highest priority). When multiple registries define the same tool,
/// the first-seen definition wins and later ones are logged as shadowed.
pub fn resolve_tools(config: &Config) -> Result<Vec<ResolvedTool>> {
    let registry_base = config.registry_dir()?;
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut resolved: Vec<ResolvedTool> = Vec::new();

    for reg in &config.registry {
        let reg_path = registry_base.join(&reg.name);
        if !reg_path.exists() {
            eprintln!(
                "  warning: registry '{}' not cloned yet, skipping",
                reg.name
            );
            continue;
        }

        let tools = load_registry_tools(&reg_path)
            .with_context(|| format!("failed to load tools from registry '{}'", reg.name))?;

        for def in tools {
            if let Some(winner) = seen.get(&def.name) {
                eprintln!(
                    "  {} shadowed: '{}' already provided by '{}'",
                    def.name, reg.name, winner
                );
            } else {
                seen.insert(def.name.clone(), reg.name.clone());
                resolved.push(ResolvedTool {
                    def,
                    registry: reg.name.clone(),
                });
            }
        }
    }

    Ok(resolved)
}

/// Apply local pins to override versions or registry sources.
///
/// If a pin specifies only a version, the version is updated in place.
/// If a pin specifies a registry, the tool is re-resolved from that
/// registry only (replacing the existing entry if present), and then
/// the pinned version is applied if one was given.
pub fn apply_pins(
    resolved: &mut Vec<ResolvedTool>,
    pins: &HashMap<String, Pin>,
    config: &Config,
) -> Result<()> {
    let registry_base = config.registry_dir()?;
    let version_re = regex::Regex::new(crate::tool::VERSION_PATTERN).unwrap();

    for (tool_name, pin) in pins {
        if let Some(ref pin_registry) = pin.registry {
            // Registry pin: re-resolve from the specified registry only.
            let reg = config.registry(pin_registry).ok_or_else(|| {
                anyhow::anyhow!(
                    "pin for '{}' references unknown registry '{}'",
                    tool_name,
                    pin_registry
                )
            })?;

            let reg_path = registry_base.join(&reg.name);
            if !reg_path.exists() {
                anyhow::bail!(
                    "pin for '{}' references registry '{}' which is not cloned",
                    tool_name,
                    pin_registry
                );
            }

            let tools = load_registry_tools(&reg_path).with_context(|| {
                format!(
                    "failed to load tools from registry '{}' for pin",
                    pin_registry
                )
            })?;

            let mut new_def = tools
                .into_iter()
                .find(|t| t.name == *tool_name)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "pin for '{}' references registry '{}' which does not contain that tool",
                        tool_name,
                        pin_registry
                    )
                })?;

            // Apply version override if specified.
            if let Some(ref version) = pin.version {
                new_def.version = version.clone();
            }

            let new_entry = ResolvedTool {
                def: new_def,
                registry: pin_registry.clone(),
            };

            // Replace existing entry or append.
            if let Some(existing) = resolved.iter_mut().find(|r| r.def.name == *tool_name) {
                *existing = new_entry;
            } else {
                resolved.push(new_entry);
            }
        } else if let Some(ref version) = pin.version {
            // Finding 15: validate pinned version before applying
            if !version_re.is_match(version) {
                anyhow::bail!(
                    "invalid pin version '{}' for '{}'",
                    version,
                    tool_name
                );
            }
            // Version-only pin: update in place.
            if let Some(existing) = resolved.iter_mut().find(|r| r.def.name == *tool_name) {
                existing.def.version = version.clone();
            } else {
                eprintln!(
                    "  warning: pin for '{}' has no matching tool to override",
                    tool_name
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Pin, Registry, Settings};
    use crate::tool::{Source, Tier, ToolDef};
    use std::collections::HashMap;

    /// Build a minimal ToolDef for testing.
    fn make_tool(name: &str, version: &str) -> ToolDef {
        ToolDef {
            name: name.to_string(),
            description: None,
            source: Source::Github,
            version: version.to_string(),
            tag_prefix: "v".to_string(),
            bin: None,
            tier: Tier::Low,
            repo: Some("owner/repo".to_string()),
            project_id: None,
            package: None,
            crate_name: None,
            aqua: None,
            assets: HashMap::new(),
            checksum: None,
            checksums: HashMap::new(),
            signature: None,
        }
    }

    /// Build a Config with a tmpdir-based cache so tests don't touch ~/.cache.
    fn make_config(registries: Vec<Registry>, pins: HashMap<String, Pin>, dir: &Path) -> Config {
        Config {
            settings: Settings {
                cache_dir: dir.to_string_lossy().to_string(),
                ..Settings::default()
            },
            registry: registries,
            pins,
        }
    }

    /// Populate a fake registry on disk: create tools/<name>.toml files.
    fn write_tool_file(registry_dir: &Path, def: &ToolDef) {
        let tools_dir = registry_dir.join("tools");
        std::fs::create_dir_all(&tools_dir).unwrap();
        let content = format!(
            r#"[tool]
name = "{name}"
source = "{source}"
version = "{version}"
tag_prefix = "v"
tier = "{tier}"
repo = "{repo}"
"#,
            name = def.name,
            source = match def.source {
                Source::Github => "github",
                Source::Gitlab => "gitlab",
                Source::Npm => "npm",
                Source::Crates => "crates",
                Source::Direct => "direct",
                Source::Rustup => "rustup",
            },
            version = def.version,
            tier = def.tier,
            repo = def.repo.as_deref().unwrap_or("owner/repo"),
        );
        let path = tools_dir.join(format!("{}.toml", def.name));
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn resolve_first_registry_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path();
        let reg_dir = cache.join("registries");

        // Create two registries with overlapping tools.
        let alpha_dir = reg_dir.join("alpha");
        let beta_dir = reg_dir.join("beta");

        // Both registries define "gh", but alpha is higher priority.
        write_tool_file(&alpha_dir, &make_tool("gh", "2.89.0"));
        write_tool_file(&alpha_dir, &make_tool("jq", "1.7.1"));
        write_tool_file(&beta_dir, &make_tool("gh", "2.88.0"));
        write_tool_file(&beta_dir, &make_tool("yq", "4.44.0"));

        let config = make_config(
            vec![
                Registry {
                    name: "alpha".to_string(),
                    url: "https://example.com/alpha.git".to_string(),
                    branch: "main".to_string(),
                    readonly: false,
                },
                Registry {
                    name: "beta".to_string(),
                    url: "https://example.com/beta.git".to_string(),
                    branch: "main".to_string(),
                    readonly: false,
                },
            ],
            HashMap::new(),
            cache,
        );

        let resolved = resolve_tools(&config).unwrap();

        // gh should come from alpha with version 2.89.0
        let gh = resolved.iter().find(|r| r.def.name == "gh").unwrap();
        assert_eq!(gh.def.version, "2.89.0");
        assert_eq!(gh.registry, "alpha");

        // jq from alpha
        let jq = resolved.iter().find(|r| r.def.name == "jq").unwrap();
        assert_eq!(jq.registry, "alpha");

        // yq from beta (no conflict)
        let yq = resolved.iter().find(|r| r.def.name == "yq").unwrap();
        assert_eq!(yq.registry, "beta");

        // Total: gh + jq + yq = 3 (beta's gh is shadowed)
        assert_eq!(resolved.len(), 3);
    }

    #[test]
    fn pin_overrides_version() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path();
        let reg_dir = cache.join("registries");

        let alpha_dir = reg_dir.join("alpha");
        write_tool_file(&alpha_dir, &make_tool("gh", "2.89.0"));

        let config = make_config(
            vec![Registry {
                name: "alpha".to_string(),
                url: "https://example.com/alpha.git".to_string(),
                branch: "main".to_string(),
                readonly: false,
            }],
            HashMap::from([(
                "gh".to_string(),
                Pin {
                    version: Some("2.90.0".to_string()),
                    registry: None,
                },
            )]),
            cache,
        );

        let mut resolved = resolve_tools(&config).unwrap();
        apply_pins(&mut resolved, &config.pins, &config).unwrap();

        let gh = resolved.iter().find(|r| r.def.name == "gh").unwrap();
        assert_eq!(gh.def.version, "2.90.0");
        assert_eq!(gh.registry, "alpha");
    }

    #[test]
    fn pin_overrides_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path();
        let reg_dir = cache.join("registries");

        let alpha_dir = reg_dir.join("alpha");
        let beta_dir = reg_dir.join("beta");

        write_tool_file(&alpha_dir, &make_tool("gh", "2.89.0"));
        write_tool_file(&beta_dir, &make_tool("gh", "2.88.0"));

        let config = make_config(
            vec![
                Registry {
                    name: "alpha".to_string(),
                    url: "https://example.com/alpha.git".to_string(),
                    branch: "main".to_string(),
                    readonly: false,
                },
                Registry {
                    name: "beta".to_string(),
                    url: "https://example.com/beta.git".to_string(),
                    branch: "main".to_string(),
                    readonly: false,
                },
            ],
            // Pin gh to beta with a specific version.
            HashMap::from([(
                "gh".to_string(),
                Pin {
                    version: Some("2.91.0".to_string()),
                    registry: Some("beta".to_string()),
                },
            )]),
            cache,
        );

        let mut resolved = resolve_tools(&config).unwrap();
        // Before pin: gh comes from alpha at 2.89.0
        assert_eq!(
            resolved.iter().find(|r| r.def.name == "gh").unwrap().registry,
            "alpha"
        );

        apply_pins(&mut resolved, &config.pins, &config).unwrap();

        // After pin: gh comes from beta at 2.91.0
        let gh = resolved.iter().find(|r| r.def.name == "gh").unwrap();
        assert_eq!(gh.def.version, "2.91.0");
        assert_eq!(gh.registry, "beta");
    }

    #[test]
    fn pin_registry_only_keeps_original_version() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path();
        let reg_dir = cache.join("registries");

        let alpha_dir = reg_dir.join("alpha");
        let beta_dir = reg_dir.join("beta");

        write_tool_file(&alpha_dir, &make_tool("gh", "2.89.0"));
        write_tool_file(&beta_dir, &make_tool("gh", "2.88.0"));

        let config = make_config(
            vec![
                Registry {
                    name: "alpha".to_string(),
                    url: "https://example.com/alpha.git".to_string(),
                    branch: "main".to_string(),
                    readonly: false,
                },
                Registry {
                    name: "beta".to_string(),
                    url: "https://example.com/beta.git".to_string(),
                    branch: "main".to_string(),
                    readonly: false,
                },
            ],
            // Pin gh to beta but no version override.
            HashMap::from([(
                "gh".to_string(),
                Pin {
                    version: None,
                    registry: Some("beta".to_string()),
                },
            )]),
            cache,
        );

        let mut resolved = resolve_tools(&config).unwrap();
        apply_pins(&mut resolved, &config.pins, &config).unwrap();

        // gh should come from beta with beta's version (2.88.0)
        let gh = resolved.iter().find(|r| r.def.name == "gh").unwrap();
        assert_eq!(gh.def.version, "2.88.0");
        assert_eq!(gh.registry, "beta");
    }

    #[test]
    fn pin_unknown_registry_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path();
        let reg_dir = cache.join("registries");
        let alpha_dir = reg_dir.join("alpha");
        write_tool_file(&alpha_dir, &make_tool("gh", "2.89.0"));

        let config = make_config(
            vec![Registry {
                name: "alpha".to_string(),
                url: "https://example.com/alpha.git".to_string(),
                branch: "main".to_string(),
                readonly: false,
            }],
            HashMap::from([(
                "gh".to_string(),
                Pin {
                    version: None,
                    registry: Some("nonexistent".to_string()),
                },
            )]),
            cache,
        );

        let mut resolved = resolve_tools(&config).unwrap();
        let result = apply_pins(&mut resolved, &config.pins, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown registry")
        );
    }

    #[test]
    fn pin_adds_tool_not_in_resolved() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path();
        let reg_dir = cache.join("registries");

        let alpha_dir = reg_dir.join("alpha");
        let beta_dir = reg_dir.join("beta");

        write_tool_file(&alpha_dir, &make_tool("gh", "2.89.0"));
        // yq only in beta, but alpha is the only configured registry
        // so resolve_tools won't find it. A registry pin can pull it in.
        write_tool_file(&beta_dir, &make_tool("yq", "4.44.0"));

        let config = make_config(
            vec![
                Registry {
                    name: "alpha".to_string(),
                    url: "https://example.com/alpha.git".to_string(),
                    branch: "main".to_string(),
                    readonly: false,
                },
                Registry {
                    name: "beta".to_string(),
                    url: "https://example.com/beta.git".to_string(),
                    branch: "main".to_string(),
                    readonly: false,
                },
            ],
            HashMap::from([(
                "yq".to_string(),
                Pin {
                    version: Some("4.45.0".to_string()),
                    registry: Some("beta".to_string()),
                },
            )]),
            cache,
        );

        // Only alpha is populated in resolve, so yq won't be there yet.
        // But beta is on disk, so the registry pin can pull it in.
        let mut resolved = resolve_tools(&config).unwrap();
        let yq_before = resolved.iter().find(|r| r.def.name == "yq");
        // yq is present from beta via normal resolution
        assert!(yq_before.is_some());

        apply_pins(&mut resolved, &config.pins, &config).unwrap();

        let yq = resolved.iter().find(|r| r.def.name == "yq").unwrap();
        assert_eq!(yq.def.version, "4.45.0");
        assert_eq!(yq.registry, "beta");
    }

    #[test]
    fn resolve_skips_missing_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path();

        // Don't create any registry dirs on disk.
        let config = make_config(
            vec![Registry {
                name: "missing".to_string(),
                url: "https://example.com/missing.git".to_string(),
                branch: "main".to_string(),
                readonly: false,
            }],
            HashMap::new(),
            cache,
        );

        let resolved = resolve_tools(&config).unwrap();
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolve_empty_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path();
        let reg_dir = cache.join("registries").join("empty");
        std::fs::create_dir_all(&reg_dir).unwrap();

        let config = make_config(
            vec![Registry {
                name: "empty".to_string(),
                url: "https://example.com/empty.git".to_string(),
                branch: "main".to_string(),
                readonly: false,
            }],
            HashMap::new(),
            cache,
        );

        let resolved = resolve_tools(&config).unwrap();
        assert!(resolved.is_empty());
    }
}
