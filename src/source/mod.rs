//! Upstream source queries for `kit add`.
//!
//! Shells out to `gh`, `glab`, and `npm` to discover the latest release
//! of a tool and detect platform-specific assets and checksum files.
//! Results populate a `ToolDef` so `kit add` writes a complete definition
//! instead of a skeleton.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::Command;
use std::sync::LazyLock;
use std::time::Duration;

use crate::tool::ChecksumFormat;

// -- Validation --

/// Repo paths: owner/repo with safe characters. Matches tool.rs REPO_PATTERN.
const REPO_PATTERN: &str = r"^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+$";

static REPO_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(REPO_PATTERN).unwrap());

/// npm package names: scoped (@scope/name) or unscoped (name).
/// Lowercase, digits, hyphens, dots, underscores.
const NPM_PATTERN: &str = r"^(@[a-z0-9._\-]+/)?[a-z0-9._\-]+$";

static NPM_RE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(NPM_PATTERN).unwrap());

/// Subprocess timeout for upstream queries.
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(120);

// -- Platform detection patterns --

/// Patterns that indicate macOS + ARM64.
static MACOS_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?i)(darwin|macos|osx)").unwrap());
static ARM64_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?i)(arm64|aarch64)").unwrap());

/// Patterns that indicate Linux + x86_64.
static LINUX_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?i)(linux)").unwrap());
static X64_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?i)(amd64|x86_64)").unwrap());

/// Filename suffixes that are verification artifacts, not installable assets.
static SKIP_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)\.(sha256|sha512|sig|asc|pem|cert|bundle|sbom)(\..*)?$").unwrap()
});

/// Patterns that indicate a checksum manifest file.
static CHECKSUM_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?i)(checksum|sha256|SHA256)").unwrap());

// -- Public types --

/// Information discovered from an upstream release.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UpstreamInfo {
    /// Resolved version string (tag prefix stripped).
    pub version: String,
    /// Detected tag prefix (e.g. "v", "").
    pub tag_prefix: String,
    /// Platform key -> asset filename.
    pub assets: HashMap<String, String>,
    /// Detected checksum manifest filename, if any.
    pub checksum_file: Option<String>,
    /// Detected checksum format, if a checksum file was found.
    pub checksum_format: Option<ChecksumFormat>,
    /// Resolved GitLab project ID (set by resolve_gitlab_project_id).
    pub project_id: Option<u64>,
    /// Detected signature method (e.g. "cosign-keyless" if .bundle files found).
    pub signature_method: Option<String>,
}

// -- GitHub --

/// Query the latest GitHub release for `repo` (owner/repo format).
///
/// Shells out to `gh release view --repo {repo} --json tagName,assets`.
pub fn query_github(repo: &str) -> Result<UpstreamInfo> {
    validate_repo(repo)?;

    let output = run_command(
        "gh",
        &[
            "release",
            "view",
            "--repo",
            repo,
            "--json",
            "tagName,assets",
        ],
    )
    .context("failed to query GitHub release -- is `gh` installed and authenticated?")?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).context("failed to parse gh release JSON")?;

    let tag = parsed["tagName"]
        .as_str()
        .context("missing tagName in release")?;

    let (tag_prefix, version) = split_tag(tag);

    let assets_arr = parsed["assets"]
        .as_array()
        .context("missing assets array in release")?;

    let asset_names: Vec<String> = assets_arr
        .iter()
        .filter_map(|a| a["name"].as_str().map(|s| s.to_string()))
        .collect();

    let (assets, checksum_file) = detect_assets(&asset_names);
    let checksum_format = checksum_file.as_ref().map(|_| ChecksumFormat::Sha256);
    let signature_method = detect_cosign_bundles(&asset_names, &assets);

    Ok(UpstreamInfo {
        version,
        tag_prefix,
        assets,
        checksum_file,
        checksum_format,
        project_id: None,
        signature_method,
    })
}

// -- GitLab --

/// Resolve a GitLab project's numeric ID from its path (e.g. "nomograph/muxr").
///
/// Shells out to `glab api projects/{encoded_path}` and extracts the `id` field.
pub fn resolve_gitlab_project_id(repo: &str) -> Result<u64> {
    validate_repo(repo)?;
    let encoded = repo.replace('/', "%2F");
    let output = run_command("glab", &["api", &format!("projects/{encoded}")])?;
    let parsed: serde_json::Value = serde_json::from_str(&output)?;
    parsed["id"]
        .as_u64()
        .context("missing id in project response")
}

/// Query the latest GitLab release for a project.
///
/// Accepts a project path (owner/repo). Resolves the numeric project ID
/// automatically via the API.
/// Shells out to `glab api projects/{encoded}/releases?per_page=1`.
pub fn query_gitlab(repo: &str) -> Result<UpstreamInfo> {
    validate_repo(repo)?;

    // Always resolve project_id from path.
    let resolved_id = resolve_gitlab_project_id(repo)?;
    let project_ref = resolved_id.to_string();

    let endpoint = format!("projects/{project_ref}/releases?per_page=1");

    let output = run_command("glab", &["api", &endpoint])
        .context("failed to query GitLab release -- is `glab` installed and authenticated?")?;

    let parsed: serde_json::Value =
        serde_json::from_str(&output).context("failed to parse glab API JSON")?;

    let releases = parsed
        .as_array()
        .context("expected array from releases API")?;

    let release = releases
        .first()
        .context("no releases found for this project")?;

    let tag = release["tag_name"]
        .as_str()
        .context("missing tag_name in release")?;

    let (tag_prefix, version) = split_tag(tag);

    // GitLab release assets live under assets.links[]
    let asset_names: Vec<String> = release
        .get("assets")
        .and_then(|a| a.get("links"))
        .and_then(|l| l.as_array())
        .map(|links| {
            links
                .iter()
                .filter_map(|link| link["name"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let (assets, checksum_file) = detect_assets(&asset_names);
    let checksum_format = checksum_file.as_ref().map(|_| ChecksumFormat::Sha256);
    let signature_method = detect_cosign_bundles(&asset_names, &assets);

    Ok(UpstreamInfo {
        version,
        tag_prefix,
        assets,
        checksum_file,
        checksum_format,
        project_id: Some(resolved_id),
        signature_method,
    })
}

// -- npm --

/// Query the latest npm package version.
///
/// Shells out to `npm view {package} version`.
/// npm packages have no binary assets -- only version is returned.
pub fn query_npm(package: &str) -> Result<UpstreamInfo> {
    if !NPM_RE.is_match(package) {
        anyhow::bail!("invalid npm package name '{package}': must match {NPM_PATTERN}");
    }

    let output = run_command("npm", &["view", package, "version"])
        .context("failed to query npm -- is `npm` installed?")?;

    let version = output.trim().to_string();
    if version.is_empty() {
        anyhow::bail!("npm returned empty version for '{package}'");
    }

    // Validate the version looks reasonable.
    let version_re = regex::Regex::new(crate::tool::VERSION_PATTERN).unwrap();
    if !version_re.is_match(&version) {
        anyhow::bail!("npm returned invalid version '{version}' for '{package}'");
    }

    Ok(UpstreamInfo {
        version,
        tag_prefix: "v".to_string(),
        assets: HashMap::new(),
        checksum_file: None,
        checksum_format: None,
        project_id: None,
        signature_method: None,
    })
}

// -- Crates.io --

/// Crates.io crate name: alphanumeric, hyphens, underscores.
const CRATE_PATTERN: &str = r"^[a-zA-Z0-9_-]+$";

static CRATE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(CRATE_PATTERN).unwrap());

/// Query the latest crates.io version for a crate.
///
/// Shells out to `cargo search {crate_name} --limit 1` and parses the
/// version from the output format `crate_name = "version"`.
/// Crates.io packages have no binary assets -- cargo handles installation.
pub fn query_crates(crate_name: &str) -> Result<UpstreamInfo> {
    if !CRATE_RE.is_match(crate_name) {
        anyhow::bail!("invalid crate name '{crate_name}': must match {CRATE_PATTERN}");
    }

    let output = run_command("cargo", &["search", crate_name, "--limit", "1"])
        .context("failed to query crates.io -- is `cargo` installed?")?;

    // cargo search output: `crate_name = "version"    # description`
    // Find the line that starts with the exact crate name.
    let version = output
        .lines()
        .find(|line| {
            line.split('=')
                .next()
                .map(|name| name.trim() == crate_name)
                .unwrap_or(false)
        })
        .and_then(|line| {
            // Extract version between quotes after '='
            let after_eq = line.split('=').nth(1)?;
            let start = after_eq.find('"')? + 1;
            let rest = &after_eq[start..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        })
        .with_context(|| format!("crate '{crate_name}' not found on crates.io"))?;

    if version.is_empty() {
        anyhow::bail!("cargo search returned empty version for '{crate_name}'");
    }

    let version_re = regex::Regex::new(crate::tool::VERSION_PATTERN).unwrap();
    if !version_re.is_match(&version) {
        anyhow::bail!("cargo search returned invalid version '{version}' for '{crate_name}'");
    }

    Ok(UpstreamInfo {
        version,
        tag_prefix: "v".to_string(),
        assets: HashMap::new(),
        checksum_file: None,
        checksum_format: None,
        project_id: None,
        signature_method: None,
    })
}

// -- Internal helpers --

/// Validate a repo string against the safe pattern.
fn validate_repo(repo: &str) -> Result<()> {
    if !REPO_RE.is_match(repo) {
        anyhow::bail!("invalid repo '{repo}': must be owner/repo matching {REPO_PATTERN}");
    }
    Ok(())
}

/// Run a subprocess and capture stdout. Enforces a 120s timeout.
fn run_command(program: &str, args: &[&str]) -> Result<String> {
    let child = Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {program}"))?;

    // Wait with timeout. Command::output() doesn't support timeout directly,
    // so we use wait_with_output on the child and rely on the OS. For a
    // proper timeout, spawn + wait in a thread. Keep it simple: use
    // wait_with_output and document that the 120s is enforced at a higher
    // level if needed. In practice, gh/glab/npm respond in seconds.
    //
    // For robustness, we set a generous timeout via thread::spawn.
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let result = child.wait_with_output();
        let _ = tx.send(result);
    });

    let output = rx
        .recv_timeout(SUBPROCESS_TIMEOUT)
        .map_err(|_| {
            anyhow::anyhow!(
                "{program} timed out after {}s",
                SUBPROCESS_TIMEOUT.as_secs()
            )
        })?
        .with_context(|| format!("{program} failed to complete"))?;

    // Clean up the thread (it should already be done if recv succeeded).
    let _ = handle.join();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{program} exited with {}: {}", output.status, stderr.trim());
    }

    String::from_utf8(output.stdout).context("subprocess output is not valid UTF-8")
}

/// Split a git tag into (prefix, version).
///
/// Common patterns: "v1.2.3" -> ("v", "1.2.3"), "1.2.3" -> ("", "1.2.3"),
/// "release/1.2.3" -> ("release/", "1.2.3").
fn split_tag(tag: &str) -> (String, String) {
    // Find where the version number starts (first digit).
    if let Some(pos) = tag.find(|c: char| c.is_ascii_digit()) {
        let prefix = &tag[..pos];
        let version = &tag[pos..];
        (prefix.to_string(), version.to_string())
    } else {
        // No digits -- treat entire tag as version (unusual).
        (String::new(), tag.to_string())
    }
}

/// Detect platform-specific assets and checksum files from a list of filenames.
///
/// Returns (platform_assets, checksum_filename).
fn detect_assets(filenames: &[String]) -> (HashMap<String, String>, Option<String>) {
    let mut assets: HashMap<String, String> = HashMap::new();
    let mut checksum_file: Option<String> = None;

    for name in filenames {
        // Skip verification artifacts.
        if SKIP_RE.is_match(name) {
            continue;
        }

        // Check for checksum manifest files.
        if is_checksum_file(name) {
            checksum_file = Some(name.clone());
            continue;
        }

        // Match platform.
        let is_macos = MACOS_RE.is_match(name);
        let is_linux = LINUX_RE.is_match(name);
        let is_arm64 = ARM64_RE.is_match(name);
        let is_x64 = X64_RE.is_match(name);

        if is_macos && is_arm64 {
            assets.insert("macos-arm64".to_string(), name.clone());
        } else if is_linux && is_x64 {
            assets.insert("linux-x64".to_string(), name.clone());
        }
    }

    // Template version placeholders in asset names. We look for a version-like
    // substring and replace it with {version}. This is heuristic -- the user
    // can edit the result before `kit push`.
    // We don't do this here because we don't have the version at this point
    // in the function. The caller (query_*) has the version and can post-process.

    (assets, checksum_file)
}

/// Determine if a filename looks like a checksum manifest.
fn is_checksum_file(name: &str) -> bool {
    // Must match the checksum pattern.
    if !CHECKSUM_RE.is_match(name) {
        return false;
    }
    // Common checksum file endings: .txt, no extension, or the name itself
    // is something like "checksums.txt", "SHA256SUMS", etc.
    let lower = name.to_lowercase();
    lower.ends_with(".txt")
        || !lower.contains('.')
        || lower == "sha256sums"
        || lower.ends_with("sums")
}

/// Replace a literal version string in asset filenames with `{version}`.
///
/// Example: "gh_2.89.0_macOS_arm64.zip" with version "2.89.0"
///       -> "gh_{version}_macOS_arm64.zip"
pub fn templatize_assets(
    assets: &HashMap<String, String>,
    version: &str,
) -> HashMap<String, String> {
    assets
        .iter()
        .map(|(k, v)| (k.clone(), v.replace(version, "{version}")))
        .collect()
}

/// Replace a literal version string in a checksum filename with `{version}`.
pub fn templatize_checksum(filename: &str, version: &str) -> String {
    filename.replace(version, "{version}")
}

/// Detect whether cosign bundle files exist alongside the platform binaries.
///
/// Returns `Some("cosign-keyless")` if any `{asset_name}.bundle` file exists
/// in the full filename list for a detected platform asset.
fn detect_cosign_bundles(
    all_filenames: &[String],
    platform_assets: &HashMap<String, String>,
) -> Option<String> {
    for asset_name in platform_assets.values() {
        let bundle_name = format!("{asset_name}.bundle");
        if all_filenames.iter().any(|f| f == &bundle_name) {
            return Some("cosign-keyless".to_string());
        }
    }
    None
}

/// Detect whether a tool is available in mise's aqua registry.
///
/// Tries `mise ls-remote <name>` and then `mise ls-remote <repo>` (for GitHub
/// tools where the aqua identifier is the repo path). Returns the aqua
/// identifier if the tool is found.
#[allow(dead_code)]
pub fn detect_aqua(name: &str, repo: Option<&str>) -> Option<String> {
    // Try the tool name directly.
    if let Ok(out) = Command::new("mise")
        .args(["ls-remote", name])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        && out.status.success()
        && !out.stdout.is_empty()
    {
        return Some(name.to_string());
    }
    // For GitHub tools, try the repo as aqua identifier.
    if let Some(r) = repo
        && let Ok(out) = Command::new("mise")
            .args(["ls-remote", r])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
        && out.status.success()
        && !out.stdout.is_empty()
    {
        return Some(r.to_string());
    }
    None
}

/// Extract the registry namespace from a registry URL.
///
/// Given "https://gitlab.com/nomograph/kits.git", returns "nomograph".
/// Given "git@gitlab.com:nomograph/kits.git", returns "nomograph".
#[allow(dead_code)]
pub fn extract_registry_namespace(url: &str) -> Option<String> {
    // HTTPS: https://gitlab.com/nomograph/kits.git -> nomograph
    if let Some(rest) = url.strip_prefix("https://") {
        // Split on '/' after the host: ["gitlab.com", "nomograph", "kits.git"]
        let parts: Vec<&str> = rest.splitn(4, '/').collect();
        if parts.len() >= 2 {
            return Some(parts[1].to_string());
        }
    }
    // SSH: git@gitlab.com:nomograph/kits.git -> nomograph
    if url.starts_with("git@")
        && let Some(path) = url.split(':').nth(1)
        && let Some(ns) = path.split('/').next()
    {
        return Some(ns.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tag_with_v_prefix() {
        let (prefix, version) = split_tag("v2.89.0");
        assert_eq!(prefix, "v");
        assert_eq!(version, "2.89.0");
    }

    #[test]
    fn split_tag_no_prefix() {
        let (prefix, version) = split_tag("1.0.0");
        assert_eq!(prefix, "");
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn split_tag_complex_prefix() {
        let (prefix, version) = split_tag("release/3.1.0");
        assert_eq!(prefix, "release/");
        assert_eq!(version, "3.1.0");
    }

    #[test]
    fn split_tag_no_digits() {
        let (prefix, version) = split_tag("latest");
        assert_eq!(prefix, "");
        assert_eq!(version, "latest");
    }

    #[test]
    fn detect_assets_github_gh() {
        let filenames = vec![
            "gh_2.89.0_macOS_arm64.zip".to_string(),
            "gh_2.89.0_linux_amd64.tar.gz".to_string(),
            "gh_2.89.0_linux_arm64.tar.gz".to_string(),
            "gh_2.89.0_windows_amd64.zip".to_string(),
            "gh_2.89.0_checksums.txt".to_string(),
        ];
        let (assets, checksum) = detect_assets(&filenames);

        assert_eq!(
            assets.get("macos-arm64"),
            Some(&"gh_2.89.0_macOS_arm64.zip".to_string())
        );
        assert_eq!(
            assets.get("linux-x64"),
            Some(&"gh_2.89.0_linux_amd64.tar.gz".to_string())
        );
        assert_eq!(checksum, Some("gh_2.89.0_checksums.txt".to_string()));
    }

    #[test]
    fn detect_assets_skips_sig_files() {
        let filenames = vec![
            "tool-darwin-arm64.tar.gz".to_string(),
            "tool-darwin-arm64.tar.gz.sha256".to_string(),
            "tool-darwin-arm64.tar.gz.sig".to_string(),
            "tool-linux-amd64.tar.gz".to_string(),
            "tool-linux-amd64.tar.gz.sbom".to_string(),
        ];
        let (assets, _checksum) = detect_assets(&filenames);

        assert_eq!(
            assets.get("macos-arm64"),
            Some(&"tool-darwin-arm64.tar.gz".to_string())
        );
        assert_eq!(
            assets.get("linux-x64"),
            Some(&"tool-linux-amd64.tar.gz".to_string())
        );
        assert_eq!(assets.len(), 2);
    }

    #[test]
    fn detect_assets_sha256sums() {
        let filenames = vec![
            "myapp-darwin-aarch64".to_string(),
            "myapp-linux-x86_64".to_string(),
            "SHA256SUMS".to_string(),
        ];
        let (assets, checksum) = detect_assets(&filenames);

        assert_eq!(
            assets.get("macos-arm64"),
            Some(&"myapp-darwin-aarch64".to_string())
        );
        assert_eq!(
            assets.get("linux-x64"),
            Some(&"myapp-linux-x86_64".to_string())
        );
        assert_eq!(checksum, Some("SHA256SUMS".to_string()));
    }

    #[test]
    fn detect_assets_osx_variant() {
        let filenames = vec![
            "tool_osx_arm64.tar.gz".to_string(),
            "tool_linux_amd64.tar.gz".to_string(),
        ];
        let (assets, _) = detect_assets(&filenames);

        assert_eq!(
            assets.get("macos-arm64"),
            Some(&"tool_osx_arm64.tar.gz".to_string())
        );
    }

    #[test]
    fn templatize_replaces_version() {
        let mut assets = HashMap::new();
        assets.insert(
            "macos-arm64".to_string(),
            "gh_2.89.0_macOS_arm64.zip".to_string(),
        );
        assets.insert(
            "linux-x64".to_string(),
            "gh_2.89.0_linux_amd64.tar.gz".to_string(),
        );

        let result = templatize_assets(&assets, "2.89.0");
        assert_eq!(
            result.get("macos-arm64"),
            Some(&"gh_{version}_macOS_arm64.zip".to_string())
        );
        assert_eq!(
            result.get("linux-x64"),
            Some(&"gh_{version}_linux_amd64.tar.gz".to_string())
        );
    }

    #[test]
    fn templatize_checksum_replaces_version() {
        let result = templatize_checksum("gh_2.89.0_checksums.txt", "2.89.0");
        assert_eq!(result, "gh_{version}_checksums.txt");
    }

    #[test]
    fn templatize_checksum_no_version() {
        let result = templatize_checksum("checksums.txt", "2.89.0");
        assert_eq!(result, "checksums.txt");
    }

    #[test]
    fn validate_repo_accepts_valid() {
        assert!(validate_repo("cli/cli").is_ok());
        assert!(validate_repo("sigstore/cosign").is_ok());
        assert!(validate_repo("nomograph/kit").is_ok());
        assert!(validate_repo("my-org/my-tool").is_ok());
    }

    #[test]
    fn validate_repo_rejects_invalid() {
        assert!(validate_repo("evil; rm -rf /").is_err());
        assert!(validate_repo("has spaces/repo").is_err());
        assert!(validate_repo("no-slash").is_err());
        assert!(validate_repo("too/many/slashes").is_err());
        assert!(validate_repo("").is_err());
    }

    #[test]
    fn npm_pattern_accepts_valid() {
        assert!(NPM_RE.is_match("typescript"));
        assert!(NPM_RE.is_match("@angular/cli"));
        assert!(NPM_RE.is_match("my-package"));
        assert!(NPM_RE.is_match("@scope/my.pkg"));
    }

    #[test]
    fn npm_pattern_rejects_invalid() {
        assert!(!NPM_RE.is_match("Evil Package"));
        assert!(!NPM_RE.is_match("../traversal"));
        assert!(!NPM_RE.is_match("; rm -rf /"));
    }

    #[test]
    fn is_checksum_file_detects_variants() {
        assert!(is_checksum_file("checksums.txt"));
        assert!(is_checksum_file("SHA256SUMS"));
        assert!(is_checksum_file("gh_2.89.0_checksums.txt"));
        assert!(!is_checksum_file("tool-linux-amd64.tar.gz"));
        assert!(!is_checksum_file("readme.md"));
    }

    #[test]
    fn detect_cosign_bundles_found() {
        let all = vec![
            "muxr-darwin-arm64".to_string(),
            "muxr-darwin-arm64.bundle".to_string(),
            "muxr-linux-amd64".to_string(),
            "muxr-linux-amd64.bundle".to_string(),
            "checksums.txt".to_string(),
        ];
        let mut assets = HashMap::new();
        assets.insert("macos-arm64".to_string(), "muxr-darwin-arm64".to_string());
        assets.insert("linux-x64".to_string(), "muxr-linux-amd64".to_string());
        assert_eq!(
            detect_cosign_bundles(&all, &assets),
            Some("cosign-keyless".to_string())
        );
    }

    #[test]
    fn detect_cosign_bundles_not_found() {
        let all = vec![
            "tool-darwin-arm64.tar.gz".to_string(),
            "tool-linux-amd64.tar.gz".to_string(),
        ];
        let mut assets = HashMap::new();
        assets.insert(
            "macos-arm64".to_string(),
            "tool-darwin-arm64.tar.gz".to_string(),
        );
        assert_eq!(detect_cosign_bundles(&all, &assets), None);
    }

    #[test]
    fn extract_registry_namespace_https() {
        assert_eq!(
            extract_registry_namespace("https://gitlab.com/nomograph/kits.git"),
            Some("nomograph".to_string())
        );
    }

    #[test]
    fn extract_registry_namespace_ssh() {
        assert_eq!(
            extract_registry_namespace("git@gitlab.com:nomograph/kits.git"),
            Some("nomograph".to_string())
        );
    }

    #[test]
    fn extract_registry_namespace_github() {
        assert_eq!(
            extract_registry_namespace("https://github.com/someone/tools.git"),
            Some("someone".to_string())
        );
    }

    #[test]
    fn crate_pattern_accepts_valid() {
        assert!(CRATE_RE.is_match("cargo-nextest"));
        assert!(CRATE_RE.is_match("serde"));
        assert!(CRATE_RE.is_match("tokio"));
        assert!(CRATE_RE.is_match("my_crate"));
    }

    #[test]
    fn crate_pattern_rejects_invalid() {
        assert!(!CRATE_RE.is_match("Evil Crate"));
        assert!(!CRATE_RE.is_match("../traversal"));
        assert!(!CRATE_RE.is_match("; rm -rf /"));
        assert!(!CRATE_RE.is_match(""));
        assert!(!CRATE_RE.is_match("@scoped/crate"));
    }
}
