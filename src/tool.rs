use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

use crate::platform::Platform;

// -- Validation patterns (security-critical: S-3, S-10) --
// F17: compile regexes once via LazyLock, not on every validate() call.

/// Tool names: lowercase alphanumeric + hyphens, must start with alphanumeric.
pub const NAME_PATTERN: &str = r"^[a-z0-9][a-z0-9-]*$";

/// Bin names: alphanumeric + underscores + hyphens.
const BIN_PATTERN: &str = r"^[a-zA-Z0-9_-]+$";

/// Version strings: digits, dots, hyphens, plus, alpha.
pub const VERSION_PATTERN: &str = r"^[0-9][0-9a-zA-Z._+\-]*$";

/// Repo paths: owner/repo with safe characters.
const REPO_PATTERN: &str = r"^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+$";

/// Tag prefixes: alphanumeric, dots, hyphens. Empty string allowed.
const TAG_PREFIX_PATTERN: &str = r"^[a-zA-Z0-9._-]*$";

/// Asset names: safe filename characters only. No path separators.
const ASSET_PATTERN: &str = r"^[a-zA-Z0-9_.{}\-]+$";

/// Branch names: alphanumeric, hyphens, slashes, dots (F9).
const BRANCH_PATTERN: &str = r"^[a-zA-Z0-9._/\-]+$";

// F17: compiled regex statics -- avoids recompilation in hot loops
static NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(NAME_PATTERN).unwrap());
static BIN_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(BIN_PATTERN).unwrap());
static VERSION_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(VERSION_PATTERN).unwrap());
static REPO_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(REPO_PATTERN).unwrap());
static ASSET_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(ASSET_PATTERN).unwrap());
static TAG_PREFIX_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(TAG_PREFIX_PATTERN).unwrap());
static BRANCH_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(BRANCH_PATTERN).unwrap());

/// Trust tiers control review policy for updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Own,
    High,
    Low,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Own => f.write_str("own"),
            Self::High => f.write_str("high"),
            Self::Low => f.write_str("low"),
        }
    }
}

/// Source type for a tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Github,
    Gitlab,
    Npm,
    Crates,
    Direct,
    Rustup,
}

/// Checksum verification format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChecksumFormat {
    Sha256,
    Sha256PerAsset,
}

/// Signature verification method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureMethod {
    CosignKeyless,
    GithubAttestation,
    None,
}

/// Checksum configuration for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumConfig {
    /// Upstream checksum filename (may contain {version} template).
    pub file: Option<String>,
    /// Format of the checksum file.
    #[serde(default = "default_checksum_format")]
    pub format: ChecksumFormat,
}

fn default_checksum_format() -> ChecksumFormat {
    ChecksumFormat::Sha256
}

/// Signature configuration for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    pub method: SignatureMethod,
    /// OIDC issuer for cosign-keyless verification.
    pub issuer: Option<String>,
    /// Certificate identity pattern for cosign verification.
    pub identity: Option<String>,
}

/// A complete tool definition, parsed from tools/<name>.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub source: Source,
    pub version: String,
    #[serde(default = "default_tag_prefix")]
    pub tag_prefix: String,
    #[serde(default)]
    pub bin: Option<String>,
    pub tier: Tier,

    // Source-specific fields
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub project_id: Option<u64>,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(rename = "crate", default)]
    pub crate_name: Option<String>,

    /// Mise aqua registry name (e.g., "cli/cli" for gh).
    /// If set, kit generates `tool = "version"` instead of `http:tool`.
    #[serde(default)]
    pub aqua: Option<String>,

    /// Per-platform asset filename templates.
    #[serde(default)]
    pub assets: HashMap<String, String>,

    /// Checksum verification config.
    #[serde(default)]
    pub checksum: Option<ChecksumConfig>,

    /// Inline pre-computed checksums (for tools without upstream checksum files).
    #[serde(default)]
    pub checksums: HashMap<String, String>,

    /// Signature verification config.
    #[serde(default)]
    pub signature: Option<SignatureConfig>,
}

fn default_tag_prefix() -> String {
    "v".to_string()
}

/// Wrapper for the TOML file structure: [tool] table at top level.
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolFile {
    pub tool: ToolDef,
}

/// Validate a tool name against NAME_PATTERN. Public for use by commands.
pub fn validate_name(name: &str) -> Result<()> {
    if !NAME_RE.is_match(name) {
        anyhow::bail!("invalid tool name '{name}': must match {NAME_PATTERN}");
    }
    Ok(())
}

/// Validate a branch name (F9). Public for config validation.
pub fn validate_branch(branch: &str) -> Result<()> {
    if !BRANCH_RE.is_match(branch) {
        anyhow::bail!("invalid branch name '{branch}': must match {BRANCH_PATTERN}");
    }
    Ok(())
}

/// F10: Validate a checksum filename after template expansion.
#[allow(dead_code)]
pub fn validate_checksum_filename(filename: &str) -> Result<()> {
    if !ASSET_RE.is_match(filename) {
        anyhow::bail!("invalid checksum filename '{filename}': must match {ASSET_PATTERN}");
    }
    Ok(())
}

impl ToolDef {
    /// Parse and validate a tool definition from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let file: ToolFile = toml::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let def = file.tool;
        def.validate()
            .with_context(|| format!("invalid tool definition: {}", path.display()))?;
        Ok(def)
    }

    /// The effective binary name.
    pub fn bin_name(&self) -> &str {
        self.bin.as_deref().unwrap_or(&self.name)
    }

    /// The git tag for the current version.
    pub fn tag(&self) -> String {
        format!("{}{}", self.tag_prefix, self.version)
    }

    /// Resolve the asset filename for a platform, expanding {version} templates.
    pub fn asset_for(&self, platform: Platform) -> Option<String> {
        let pattern = self.assets.get(platform.key())?;
        Some(pattern.replace("{version}", &self.version))
    }

    /// Resolve the download URL for a platform.
    pub fn url_for(&self, platform: Platform) -> Option<String> {
        let asset = self.asset_for(platform)?;
        let tag = self.tag();

        match self.source {
            Source::Github => {
                let repo = self.repo.as_ref()?;
                Some(format!(
                    "https://github.com/{repo}/releases/download/{tag}/{asset}"
                ))
            }
            Source::Gitlab => {
                if let Some(pid) = self.project_id {
                    // Own tools: generic package registry
                    Some(format!(
                        "https://gitlab.com/api/v4/projects/{pid}/packages/generic/{name}/{tag}/{asset}",
                        name = self.name
                    ))
                } else {
                    let repo = self.repo.as_ref()?;
                    // Third-party: release download
                    Some(format!(
                        "https://gitlab.com/{repo}/-/releases/{tag}/downloads/{asset}"
                    ))
                }
            }
            Source::Direct => {
                // For direct sources, the asset IS the full URL (after version expansion)
                Some(asset)
            }
            // npm, crates, rustup don't have download URLs -- mise handles them
            _ => None,
        }
    }

    /// Resolve the checksum file URL for a platform.
    /// F10: validates the expanded filename against ASSET_PATTERN.
    pub fn checksum_url(&self) -> Option<String> {
        let cfg = self.checksum.as_ref()?;
        let file = cfg.file.as_ref()?;
        let filename = file.replace("{version}", &self.version);
        // F10: validate expanded checksum filename
        if !ASSET_RE.is_match(&filename) {
            eprintln!("  warning: invalid checksum filename '{filename}', skipping");
            return None;
        }
        let tag = self.tag();

        match self.source {
            Source::Github => {
                let repo = self.repo.as_ref()?;
                Some(format!(
                    "https://github.com/{repo}/releases/download/{tag}/{filename}"
                ))
            }
            Source::Gitlab => {
                if let Some(pid) = self.project_id {
                    Some(format!(
                        "https://gitlab.com/api/v4/projects/{pid}/packages/generic/{name}/{tag}/{filename}",
                        name = self.name
                    ))
                } else {
                    let repo = self.repo.as_ref()?;
                    Some(format!(
                        "https://gitlab.com/{repo}/-/releases/{tag}/downloads/{filename}"
                    ))
                }
            }
            _ => None,
        }
    }

    /// Validate all fields against security patterns.
    /// This is the security-critical boundary (S-3, S-10).
    pub fn validate(&self) -> Result<()> {
        if !NAME_RE.is_match(&self.name) {
            anyhow::bail!(
                "invalid tool name '{}': must match {NAME_PATTERN}",
                self.name
            );
        }

        if !VERSION_RE.is_match(&self.version) {
            anyhow::bail!(
                "invalid version '{}' for {}: must match {VERSION_PATTERN}",
                self.version,
                self.name
            );
        }

        if !TAG_PREFIX_RE.is_match(&self.tag_prefix) {
            anyhow::bail!(
                "invalid tag_prefix '{}' for {}: must match {TAG_PREFIX_PATTERN}",
                self.tag_prefix,
                self.name
            );
        }

        // Finding 11: validate direct source URLs are HTTPS
        if self.source == Source::Direct {
            for (platform, url) in &self.assets {
                let expanded = url.replace("{version}", &self.version);
                if !expanded.to_lowercase().starts_with("https://") {
                    anyhow::bail!(
                        "direct source URL for {} ({}) must use https://",
                        self.name,
                        platform
                    );
                }
            }
        }

        if let Some(ref bin) = self.bin
            && !BIN_RE.is_match(bin)
        {
            anyhow::bail!(
                "invalid bin name '{}' for {}: must match {BIN_PATTERN}",
                bin,
                self.name
            );
        }

        if let Some(ref repo) = self.repo
            && !REPO_RE.is_match(repo)
        {
            anyhow::bail!(
                "invalid repo '{}' for {}: must match {REPO_PATTERN}",
                repo,
                self.name
            );
        }

        // Validate asset names: no path separators, no percent-encoding
        for (platform, asset) in &self.assets {
            if Platform::from_key(platform).is_none() {
                anyhow::bail!(
                    "unknown platform '{}' in assets for {}",
                    platform,
                    self.name
                );
            }
            // For direct sources, assets are full URLs -- skip pattern check
            if self.source != Source::Direct && !ASSET_RE.is_match(asset) {
                anyhow::bail!(
                    "invalid asset name '{}' for {} ({}): must match {ASSET_PATTERN}",
                    asset,
                    self.name,
                    platform
                );
            }
        }

        // Source-specific required fields
        match self.source {
            Source::Github => {
                if self.repo.is_none() {
                    anyhow::bail!("{}: github source requires 'repo' field", self.name);
                }
            }
            Source::Gitlab => {
                if self.project_id.is_none() && self.repo.is_none() {
                    anyhow::bail!(
                        "{}: gitlab source requires either 'project_id' or 'repo'",
                        self.name
                    );
                }
            }
            Source::Npm => {
                // package defaults to name, so no required field
            }
            Source::Crates => {
                // crate defaults to name, so no required field
            }
            Source::Direct => {
                if self.assets.is_empty() {
                    anyhow::bail!("{}: direct source requires 'assets' with URLs", self.name);
                }
            }
            Source::Rustup => {}
        }

        // T3-6: validate inline checksums are valid hex hashes
        for (platform, hash) in &self.checksums {
            if Platform::from_key(platform).is_none() {
                anyhow::bail!(
                    "unknown platform '{}' in checksums for {}",
                    platform,
                    self.name
                );
            }
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                anyhow::bail!(
                    "invalid inline checksum for {} ({}): must be 64 hex chars, got '{}'",
                    self.name,
                    platform,
                    hash
                );
            }
        }

        Ok(())
    }
}

/// Registry metadata from _meta.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RegistryMeta {
    pub registry: RegistryInfo,
    #[serde(default)]
    pub policy: RegistryPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RegistryInfo {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub maintainer: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RegistryPolicy {
    #[serde(default)]
    pub auto_merge_tiers: Vec<Tier>,
    #[serde(default)]
    pub auto_merge_bump: Vec<String>,
    #[serde(default = "default_true")]
    pub auto_merge_requires_checksum: bool,
}

#[allow(dead_code)]
fn default_true() -> bool {
    true
}

/// Load all tool definitions from a registry directory.
pub fn load_registry_tools(registry_dir: &Path) -> Result<Vec<ToolDef>> {
    let tools_dir = registry_dir.join("tools");
    if !tools_dir.exists() {
        return Ok(vec![]);
    }

    let mut tools = Vec::new();
    for entry in std::fs::read_dir(&tools_dir)
        .with_context(|| format!("failed to read {}", tools_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        // Finding 3: reject symlinks to prevent path traversal from malicious registries
        if entry.file_type().map(|ft| ft.is_symlink()).unwrap_or(false) {
            eprintln!("  warning: skipping symlink {}", path.display());
            continue;
        }

        // Skip _meta.toml and non-TOML files
        if path.file_name().map(|n| n == "_meta.toml").unwrap_or(false) {
            continue;
        }
        if path.extension().map(|e| e != "toml").unwrap_or(true) {
            continue;
        }

        match ToolDef::load(&path) {
            Ok(def) => tools.push(def),
            Err(e) => {
                eprintln!("  warning: skipping {}: {e}", path.display());
            }
        }
    }

    tools.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(tools)
}

/// Load registry metadata from _meta.toml.
#[allow(dead_code)]
pub fn load_registry_meta(registry_dir: &Path) -> Result<RegistryMeta> {
    let path = registry_dir.join("tools").join("_meta.toml");
    if !path.exists() {
        anyhow::bail!("no _meta.toml found in {}", registry_dir.display());
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let meta: RegistryMeta = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tool_name() {
        let re = regex::Regex::new(NAME_PATTERN).unwrap();
        assert!(re.is_match("gh"));
        assert!(re.is_match("claude-code"));
        assert!(re.is_match("git-lfs"));
        assert!(re.is_match("yq"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("-bad"));
        assert!(!re.is_match("Bad"));
        assert!(!re.is_match("../evil"));
        assert!(!re.is_match("foo/bar"));
    }

    #[test]
    fn valid_version() {
        let re = regex::Regex::new(VERSION_PATTERN).unwrap();
        assert!(re.is_match("2.89.0"));
        assert!(re.is_match("1.0.0-beta.1"));
        assert!(re.is_match("0.11.3"));
        assert!(re.is_match("5.3.4"));
        assert!(re.is_match("30.2"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("v1.0.0"));
        assert!(!re.is_match("abc"));
    }

    #[test]
    fn valid_asset_name() {
        let re = regex::Regex::new(ASSET_PATTERN).unwrap();
        assert!(re.is_match("gh_{version}_macOS_arm64.zip"));
        assert!(re.is_match("muxr-darwin-arm64"));
        assert!(re.is_match("checksums.txt"));
        assert!(!re.is_match("../../etc/passwd"));
        assert!(!re.is_match("foo/bar.tar.gz"));
        assert!(!re.is_match("evil%2F..%2Fpasswd"));
    }

    #[test]
    fn url_generation_github() {
        let def = ToolDef {
            name: "gh".to_string(),
            description: None,
            source: Source::Github,
            version: "2.89.0".to_string(),
            tag_prefix: "v".to_string(),
            bin: Some("gh".to_string()),
            tier: Tier::High,
            repo: Some("cli/cli".to_string()),
            project_id: None,
            package: None,
            crate_name: None,
            aqua: Some("cli/cli".to_string()),
            assets: HashMap::from([
                ("macos-arm64".to_string(), "gh_{version}_macOS_arm64.zip".to_string()),
                ("linux-x64".to_string(), "gh_{version}_linux_amd64.tar.gz".to_string()),
            ]),
            checksum: Some(ChecksumConfig {
                file: Some("gh_{version}_checksums.txt".to_string()),
                format: ChecksumFormat::Sha256,
            }),
            checksums: HashMap::new(),
            signature: None,
        };

        assert_eq!(
            def.url_for(Platform::MacosArm64).unwrap(),
            "https://github.com/cli/cli/releases/download/v2.89.0/gh_2.89.0_macOS_arm64.zip"
        );
        assert_eq!(def.tag(), "v2.89.0");
        assert_eq!(def.bin_name(), "gh");
    }

    #[test]
    fn url_generation_gitlab_own() {
        let def = ToolDef {
            name: "muxr".to_string(),
            description: None,
            source: Source::Gitlab,
            version: "0.6.2".to_string(),
            tag_prefix: "v".to_string(),
            bin: Some("muxr".to_string()),
            tier: Tier::Own,
            repo: None,
            project_id: Some(80663080),
            package: None,
            crate_name: None,
            aqua: None,
            assets: HashMap::from([
                ("macos-arm64".to_string(), "muxr-darwin-arm64".to_string()),
                ("linux-x64".to_string(), "muxr-linux-amd64".to_string()),
            ]),
            checksum: Some(ChecksumConfig {
                file: Some("checksums.txt".to_string()),
                format: ChecksumFormat::Sha256,
            }),
            checksums: HashMap::new(),
            signature: Some(SignatureConfig {
                method: SignatureMethod::CosignKeyless,
                issuer: Some("https://gitlab.com".to_string()),
                identity: Some("https://gitlab.com/nomograph/muxr".to_string()),
            }),
        };

        assert_eq!(
            def.url_for(Platform::MacosArm64).unwrap(),
            "https://gitlab.com/api/v4/projects/80663080/packages/generic/muxr/v0.6.2/muxr-darwin-arm64"
        );
    }

    #[test]
    fn validation_rejects_path_traversal() {
        let mut def = make_valid_tool();
        def.name = "../evil".to_string();
        assert!(def.validate().is_err());

        let mut def = make_valid_tool();
        def.bin = Some("../../passwd".to_string());
        assert!(def.validate().is_err());
    }

    #[test]
    fn validation_rejects_bad_repo() {
        let mut def = make_valid_tool();
        def.repo = Some("evil; rm -rf /".to_string());
        assert!(def.validate().is_err());
    }

    fn make_valid_tool() -> ToolDef {
        ToolDef {
            name: "test-tool".to_string(),
            description: None,
            source: Source::Github,
            version: "1.0.0".to_string(),
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
}
