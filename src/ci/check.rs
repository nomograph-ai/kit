//! Phase 1: Check upstream releases and compute checksums.
//!
//! Deterministic work only -- no LLM calls. For each tool in the registry:
//! 1. Query the upstream release API for the latest stable version
//! 2. If newer than pinned, download release assets for both platforms
//! 3. Compute SHA256 checksums of downloaded assets
//! 4. Verify against upstream-published checksum files where available
//! 5. Query GitHub Advisory Database for known CVEs on the pinned version
//!
//! Output: updates.json with update candidates for Phase 2.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read;

use crate::platform::Platform;
use crate::tool::{self, ChecksumFormat, Source, ToolDef};
use crate::verify;

use super::{Advisory, CheckOutput, UpdateCandidate};

const PLATFORMS: [Platform; 2] = [Platform::MacosArm64, Platform::LinuxX64];

/// Run the check phase: scan all tools for upstream updates.
///
/// `registry_dir` is the path to the registry root (containing `tools/`).
/// Results are written to `output` as JSON.
pub fn check(registry_dir: &Path, output: &Path) -> Result<()> {
    let tools = tool::load_registry_tools(registry_dir)?;
    let total = tools.len();

    eprintln!("kit check: scanning {} tools for updates\n", total);

    let mut updates: Vec<UpdateCandidate> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut advisories: HashMap<String, Vec<Advisory>> = HashMap::new();

    for def in &tools {
        match check_tool(def) {
            Ok(Some(candidate)) => {
                // Check for checksum mismatches -- record as error
                for (platform, verified) in &candidate.verified {
                    if *verified == Some(false) {
                        errors.push(format!(
                            "CHECKSUM MISMATCH: {} {} -- computed hash does not match upstream!",
                            candidate.name, platform
                        ));
                    }
                }
                eprintln!(
                    "  {}: {} -> {}",
                    candidate.name, candidate.current_version, candidate.new_version
                );
                updates.push(candidate);
            }
            Ok(None) => {
                eprintln!("  {}: {} (up to date)", def.name, def.version);
            }
            Err(e) => {
                eprintln!("  error checking {}: {e:#}", def.name);
                errors.push(format!("{}: {e}", def.name));
            }
        }

        // Check for known vulnerabilities on the current pinned version
        match check_advisories(def) {
            Ok(advs) if !advs.is_empty() => {
                for a in &advs {
                    eprintln!(
                        "  ADVISORY: {} {} -- {} ({}): {}",
                        def.name, def.version, a.id, a.severity, a.summary
                    );
                }
                advisories.insert(def.name.clone(), advs);
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("  warning: advisory check failed for {}: {e}", def.name);
            }
        }
    }

    let result = CheckOutput {
        updates_found: updates.len(),
        updates,
        errors,
        advisories,
        tools_checked: total,
    };

    let json = serde_json::to_string_pretty(&result).context("failed to serialize updates.json")?;
    std::fs::write(output, &json)
        .with_context(|| format!("failed to write {}", output.display()))?;

    eprintln!("\n{}", "=".repeat(60));
    eprintln!("Checked: {total}");
    eprintln!("Updates: {}", result.updates_found);
    eprintln!("Advisories: {}", result.advisories.len());
    eprintln!("Errors:  {}", result.errors.len());

    let mismatches: Vec<&String> = result
        .errors
        .iter()
        .filter(|e| e.contains("CHECKSUM MISMATCH"))
        .collect();

    if !mismatches.is_empty() {
        eprintln!("\nFATAL: {} checksum mismatch(es) detected:", mismatches.len());
        for m in &mismatches {
            eprintln!("  - {m}");
        }
        anyhow::bail!(
            "{} tool(s) failed checksum verification -- possible supply chain compromise",
            mismatches.len()
        );
    }

    Ok(())
}

/// Check a single tool for upstream updates.
/// Returns `Ok(None)` if already up to date.
fn check_tool(def: &ToolDef) -> Result<Option<UpdateCandidate>> {
    match def.source {
        Source::Github => check_github(def),
        Source::Gitlab => check_gitlab(def),
        Source::Npm => check_npm(def),
        Source::Crates => check_crates(def),
        Source::Direct => {
            eprintln!(
                "  {}: {} (skip -- direct source has no upstream release API to check)",
                def.name, def.version
            );
            Ok(None)
        }
        Source::Rustup => {
            eprintln!(
                "  {}: {} (skip -- version managed by rustup, not a registry release)",
                def.name, def.version
            );
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Source-specific checkers
// ---------------------------------------------------------------------------

fn check_github(def: &ToolDef) -> Result<Option<UpdateCandidate>> {
    let repo = def
        .repo
        .as_deref()
        .context("github source requires 'repo' field")?;

    let tag = match gh_latest_stable_tag(repo)? {
        Some(t) => t,
        None => return Ok(None),
    };

    let latest = extract_version(&tag, &def.tag_prefix);
    if latest == def.version {
        return Ok(None);
    }

    let mut candidate = UpdateCandidate {
        name: def.name.clone(),
        current_version: def.version.clone(),
        new_version: latest.clone(),
        tag: tag.clone(),
        checksums: HashMap::new(),
        verified: HashMap::new(),
        note: None,
    };

    let tmp = tempfile::tempdir().context("failed to create temp dir")?;

    for platform in &PLATFORMS {
        download_and_verify(def, &latest, &tag, *platform, tmp.path(), &mut candidate)?;
    }

    Ok(Some(candidate))
}

fn check_gitlab(def: &ToolDef) -> Result<Option<UpdateCandidate>> {
    let project_ref = if let Some(pid) = def.project_id {
        pid.to_string()
    } else if let Some(ref repo) = def.repo {
        repo.replace('/', "%2F")
    } else {
        anyhow::bail!("gitlab source requires project_id or repo");
    };

    let output = run_cmd(
        "glab",
        &["api", &format!("projects/{project_ref}/releases?per_page=5")],
        None,
    )?;

    let releases: Vec<serde_json::Value> =
        serde_json::from_str(&output).context("failed to parse gitlab releases JSON")?;

    if releases.is_empty() {
        return Ok(None);
    }

    // Find latest non-upcoming release
    let release = releases
        .iter()
        .find(|r| !r["upcoming_release"].as_bool().unwrap_or(false))
        .unwrap_or(&releases[0]);

    let tag = release["tag_name"]
        .as_str()
        .context("missing tag_name in release")?
        .to_string();

    let latest = extract_version(&tag, &def.tag_prefix);
    if latest == def.version {
        return Ok(None);
    }

    let mut candidate = UpdateCandidate {
        name: def.name.clone(),
        current_version: def.version.clone(),
        new_version: latest.clone(),
        tag: tag.clone(),
        checksums: HashMap::new(),
        verified: HashMap::new(),
        note: None,
    };

    let tmp = tempfile::tempdir().context("failed to create temp dir")?;

    // For own tools with project_id, resolve asset URLs from the release links
    if def.project_id.is_some() {
        for platform in &PLATFORMS {
            let asset_name = match asset_name_for(def, &latest, *platform) {
                Some(n) => n,
                None => continue,
            };

            // Search release asset links
            let links = release["assets"]["links"].as_array();
            let url = links.and_then(|ls| {
                ls.iter().find_map(|link| {
                    let name = link["name"].as_str().unwrap_or("");
                    let link_url = link["direct_asset_url"]
                        .as_str()
                        .or_else(|| link["url"].as_str());
                    if name == asset_name || link_url.is_some_and(|u| u.contains(&asset_name)) {
                        link_url.map(|s| s.to_string())
                    } else {
                        None
                    }
                })
            });

            match url {
                Some(u) => {
                    download_and_verify_url(
                        def,
                        &latest,
                        &tag,
                        *platform,
                        &asset_name,
                        &u,
                        tmp.path(),
                        &mut candidate,
                    )?;
                }
                None => {
                    eprintln!(
                        "    {}: no download link found in release for {}",
                        platform.key(),
                        asset_name
                    );
                }
            }
        }
    } else {
        // Third-party gitlab tool -- standard release download URLs
        for platform in &PLATFORMS {
            download_and_verify(def, &latest, &tag, *platform, tmp.path(), &mut candidate)?;
        }
    }

    Ok(Some(candidate))
}

fn check_npm(def: &ToolDef) -> Result<Option<UpdateCandidate>> {
    let package = def.package.as_deref().unwrap_or(&def.name);

    let output = run_cmd("npm", &["view", package, "version"], None)?;
    let latest = output.trim().to_string();

    if latest.is_empty() || latest == def.version {
        return Ok(None);
    }

    Ok(Some(UpdateCandidate {
        name: def.name.clone(),
        current_version: def.version.clone(),
        new_version: latest,
        tag: String::new(),
        checksums: HashMap::new(),
        verified: HashMap::new(),
        note: Some("npm package -- integrity verified by npm on install".to_string()),
    }))
}

fn check_crates(def: &ToolDef) -> Result<Option<UpdateCandidate>> {
    let crate_name = def.crate_name.as_deref().unwrap_or(&def.name);

    let output = run_cmd("cargo", &["search", crate_name, "--limit", "1"], None)?;

    // Parse: crate_name = "version"
    let latest = output
        .lines()
        .find(|line| line.starts_with(crate_name))
        .and_then(|line| {
            let start = line.find('"')?;
            let end = line[start + 1..].find('"')?;
            Some(line[start + 1..start + 1 + end].to_string())
        });

    let latest = match latest {
        Some(v) if v != def.version => v,
        _ => return Ok(None),
    };

    Ok(Some(UpdateCandidate {
        name: def.name.clone(),
        current_version: def.version.clone(),
        new_version: latest,
        tag: String::new(),
        checksums: HashMap::new(),
        verified: HashMap::new(),
        note: Some("cargo crate -- checksums verified by cargo on install".to_string()),
    }))
}

// ---------------------------------------------------------------------------
// Download and verification helpers
// ---------------------------------------------------------------------------

/// Resolve the asset filename for a tool at a given version and platform.
fn asset_name_for(def: &ToolDef, version: &str, platform: Platform) -> Option<String> {
    let pattern = def.assets.get(platform.key())?;
    Some(pattern.replace("{version}", version))
}

/// Build the download URL for an asset.
fn asset_url_for(def: &ToolDef, version: &str, tag: &str, platform: Platform) -> Option<String> {
    let asset = asset_name_for(def, version, platform)?;

    match def.source {
        Source::Github => {
            let repo = def.repo.as_ref()?;
            Some(format!(
                "https://github.com/{repo}/releases/download/{tag}/{asset}"
            ))
        }
        Source::Gitlab => {
            if let Some(pid) = def.project_id {
                Some(format!(
                    "https://gitlab.com/api/v4/projects/{pid}/packages/generic/{name}/{tag}/{asset}",
                    name = def.name
                ))
            } else {
                let repo = def.repo.as_ref()?;
                Some(format!(
                    "https://gitlab.com/{repo}/-/releases/{tag}/downloads/{asset}"
                ))
            }
        }
        Source::Direct => Some(asset),
        _ => None,
    }
}

/// Build the checksum file URL for a tool at a given version and tag.
fn checksum_url_for(
    def: &ToolDef,
    version: &str,
    tag: &str,
    platform: Platform,
) -> Option<String> {
    let cfg = def.checksum.as_ref()?;
    let file = cfg.file.as_ref()?;

    let filename = if cfg.format == ChecksumFormat::Sha256PerAsset {
        let asset = asset_name_for(def, version, platform)?;
        format!("{asset}.sha256")
    } else {
        file.replace("{version}", version)
    };

    match def.source {
        Source::Github => {
            let repo = def.repo.as_ref()?;
            Some(format!(
                "https://github.com/{repo}/releases/download/{tag}/{filename}"
            ))
        }
        Source::Gitlab => {
            if let Some(pid) = def.project_id {
                Some(format!(
                    "https://gitlab.com/api/v4/projects/{pid}/packages/generic/{name}/{tag}/{filename}",
                    name = def.name
                ))
            } else {
                let repo = def.repo.as_ref()?;
                Some(format!(
                    "https://gitlab.com/{repo}/-/releases/{tag}/downloads/{filename}"
                ))
            }
        }
        _ => None,
    }
}

/// Download an asset and verify its checksum, populating the candidate struct.
fn download_and_verify(
    def: &ToolDef,
    version: &str,
    tag: &str,
    platform: Platform,
    tmp_dir: &Path,
    candidate: &mut UpdateCandidate,
) -> Result<()> {
    let asset_name = match asset_name_for(def, version, platform) {
        Some(n) => n,
        None => return Ok(()),
    };

    let url = match asset_url_for(def, version, tag, platform) {
        Some(u) => u,
        None => return Ok(()),
    };

    download_and_verify_url(def, version, tag, platform, &asset_name, &url, tmp_dir, candidate)
}

/// Download from a specific URL and verify checksum.
#[allow(clippy::too_many_arguments)]
fn download_and_verify_url(
    def: &ToolDef,
    version: &str,
    tag: &str,
    platform: Platform,
    asset_name: &str,
    url: &str,
    tmp_dir: &Path,
    candidate: &mut UpdateCandidate,
) -> Result<()> {
    let asset_path = tmp_dir.join(format!("{}-{asset_name}", platform.key()));

    eprintln!("    downloading {}: {asset_name}", platform.key());

    let client = https_client()?;
    let download = |client: &reqwest::blocking::Client, url: &str, path: &std::path::Path| -> Result<Option<usize>> {
        match client.get(url).send() {
            Ok(resp) if resp.status().is_success() => {
                let content_length = resp.content_length().map(|l| l as usize);
                let bytes = resp.bytes().context("failed to read response body")?;
                let actual_len = bytes.len();
                std::fs::write(path, &bytes)
                    .with_context(|| format!("failed to write {}", path.display()))?;
                // Verify download completeness
                if let Some(expected) = content_length
                    && actual_len != expected
                {
                    anyhow::bail!(
                        "incomplete download: got {} bytes, expected {}",
                        actual_len,
                        expected
                    );
                }
                Ok(Some(actual_len))
            }
            Ok(resp) => {
                eprintln!(
                    "    warning: download failed for {} (HTTP {})",
                    platform.key(),
                    resp.status()
                );
                Ok(None)
            }
            Err(e) => {
                eprintln!("    warning: download failed for {}: {e}", platform.key());
                Ok(None)
            }
        }
    };

    match download(&client, url, &asset_path)? {
        Some(_) => {}
        None => {
            candidate
                .checksums
                .insert(platform.key().to_string(), None);
            return Ok(());
        }
    }

    // Compute SHA256 of the downloaded asset
    let computed = compute_sha256_file(&asset_path)?;
    candidate
        .checksums
        .insert(platform.key().to_string(), Some(computed.clone()));

    // Try to verify against upstream checksum file
    if def.checksum.is_some() {
        let checksum_url = checksum_url_for(def, version, tag, platform);
        if let Some(csum_url) = checksum_url {
            let csum_path = tmp_dir.join(format!("checksum-{}.txt", platform.key()));
            match client.get(&csum_url).send() {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.text().context("failed to read checksum body")?;
                    std::fs::write(&csum_path, &body)?;

                    let format = def
                        .checksum
                        .as_ref()
                        .map(|c| &c.format)
                        .unwrap_or(&ChecksumFormat::Sha256);

                    match verify::parse_checksum_file(&body, asset_name, format) {
                        Ok(Some(expected)) => {
                            if computed == expected {
                                eprintln!("    {}: checksum VERIFIED", platform.key());
                                candidate
                                    .verified
                                    .insert(platform.key().to_string(), Some(true));
                            } else {
                                // Retry once -- mismatch may be a corrupt download
                                eprintln!(
                                    "    {}: checksum mismatch, retrying download...",
                                    platform.key()
                                );
                                let retry_ok = if let Ok(Some(_)) = download(&client, url, &asset_path) {
                                    let retry_hash = compute_sha256_file(&asset_path)?;
                                    retry_hash == expected
                                } else {
                                    false
                                };
                                if retry_ok {
                                    eprintln!("    {}: checksum VERIFIED (retry)", platform.key());
                                    // Update computed hash to the correct one
                                    candidate
                                        .checksums
                                        .insert(platform.key().to_string(), Some(expected.clone()));
                                    candidate
                                        .verified
                                        .insert(platform.key().to_string(), Some(true));
                                } else {
                                    let retry_hash = compute_sha256_file(&asset_path).unwrap_or_default();
                                    eprintln!(
                                        "    ERROR: {} checksum MISMATCH (confirmed)! expected={}, got={}",
                                        platform.key(),
                                        expected,
                                        retry_hash
                                    );
                                    candidate
                                        .verified
                                        .insert(platform.key().to_string(), Some(false));
                                }
                            }
                        }
                        Ok(None) => {
                            eprintln!(
                                "    warning: {} not found in checksum file",
                                asset_name
                            );
                            candidate
                                .verified
                                .insert(platform.key().to_string(), None);
                        }
                        Err(e) => {
                            eprintln!(
                                "    warning: checksum parse error for {}: {e}",
                                platform.key()
                            );
                            candidate
                                .verified
                                .insert(platform.key().to_string(), None);
                        }
                    }
                }
                Ok(_) => {
                    eprintln!(
                        "    warning: could not download checksum file for {}",
                        platform.key()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "    warning: checksum download failed for {}: {e}",
                        platform.key()
                    );
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Advisory checking
// ---------------------------------------------------------------------------

/// Query the GitHub Advisory Database for known CVEs on the pinned version.
fn check_advisories(def: &ToolDef) -> Result<Vec<Advisory>> {
    let repo = match def.repo.as_deref() {
        Some(r) if def.source == Source::Github => r,
        _ => return Ok(vec![]),
    };

    let version = &def.version;
    let jq_filter = format!(
        r#"[.[] | select(.vulnerabilities[]?.vulnerable_version_range | test("{version}"))]"#
    );

    let output = match run_cmd_opt(
        "gh",
        &[
            "api",
            &format!("repos/{repo}/security-advisories"),
            "--jq",
            &jq_filter,
        ],
        None,
    ) {
        Some(out) => out,
        None => return Ok(vec![]),
    };

    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed == "[]" || trimmed == "null" {
        return Ok(vec![]);
    }

    let raw: Vec<serde_json::Value> =
        serde_json::from_str(trimmed).unwrap_or_default();

    Ok(raw
        .iter()
        .map(|a| Advisory {
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

// ---------------------------------------------------------------------------
// Upstream version query helpers
// ---------------------------------------------------------------------------

/// Get the latest stable tag from a GitHub repo using `gh`.
fn gh_latest_stable_tag(repo: &str) -> Result<Option<String>> {
    // First try `gh release view` for the latest release
    let output = run_cmd_opt(
        "gh",
        &[
            "release",
            "view",
            "--repo",
            repo,
            "--json",
            "tagName,isPrerelease",
        ],
        None,
    );

    if let Some(text) = output {
        let parsed: serde_json::Value =
            serde_json::from_str(&text).context("failed to parse gh release view output")?;

        if !parsed["isPrerelease"].as_bool().unwrap_or(true)
            && let Some(tag) = parsed["tagName"].as_str()
        {
            return Ok(Some(tag.to_string()));
        }
    }

    // Fall back to listing releases and finding the latest stable one
    let list_output = run_cmd_opt(
        "gh",
        &[
            "release",
            "list",
            "--repo",
            repo,
            "--limit",
            "10",
            "--json",
            "tagName,isPrerelease,isLatest",
        ],
        None,
    );

    if let Some(text) = list_output {
        let releases: Vec<serde_json::Value> =
            serde_json::from_str(&text).unwrap_or_default();

        // Find first non-prerelease
        for r in &releases {
            if !r["isPrerelease"].as_bool().unwrap_or(true)
                && let Some(tag) = r["tagName"].as_str()
            {
                return Ok(Some(tag.to_string()));
            }
        }
    }

    Ok(None)
}

/// Strip tag prefix to get version string.
fn extract_version(tag: &str, prefix: &str) -> String {
    if !prefix.is_empty() && tag.starts_with(prefix) {
        tag[prefix.len()..].to_string()
    } else {
        tag.to_string()
    }
}

// ---------------------------------------------------------------------------
// Infrastructure
// ---------------------------------------------------------------------------

/// Build an HTTPS-only reqwest blocking client with 60s timeout.
fn https_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("failed to build HTTP client")
}

/// Compute SHA256 of a file, returning the hex digest.
fn compute_sha256_file(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("read error on {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Run a subprocess command, returning stdout on success.
fn run_cmd(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let output = cmd
        .output()
        .with_context(|| format!("failed to execute {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "{program} {} failed (exit {}): {}",
            args.first().unwrap_or(&""),
            output.status,
            stderr.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a subprocess command, returning None on any failure instead of an error.
fn run_cmd_opt(program: &str, args: &[&str], cwd: Option<&Path>) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).to_string())
}
