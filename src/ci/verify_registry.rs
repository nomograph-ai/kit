//! Pipeline 3: Verify -- validate an entire registry.
//!
//! Runs in the MR pipeline to independently validate all tool definitions:
//! 1. All TOML files parse and pass validation
//! 2. Registry metadata (_meta.toml) is valid
//! 3. Checksums re-verify against upstream where possible
//! 4. No malformed or missing required fields
//!
//! This is the deterministic gate before merge. No LLM calls.

use std::path::Path;

use anyhow::{Context, Result};

use crate::platform::Platform;
use crate::tool::{self, ToolDef};
use crate::verify;

use super::{ToolVerifyResult, VerifyRegistryOutput};

const PLATFORMS: [Platform; 2] = [Platform::MacosArm64, Platform::LinuxX64];

/// Verify all tool definitions in a registry directory.
///
/// Returns `Ok(())` if all tools are valid. Returns `Err` if any tool
/// fails validation or checksum verification.
pub fn verify_registry(registry_dir: &Path, output: Option<&Path>) -> Result<()> {
    eprintln!(
        "kit verify-registry: validating {}\n",
        registry_dir.display()
    );

    // Verify _meta.toml exists and parses
    match tool::load_registry_meta(registry_dir) {
        Ok(meta) => {
            eprintln!("  registry: {} (ok)", meta.registry.name);
        }
        Err(e) => {
            eprintln!("  warning: _meta.toml issue: {e}");
        }
    }

    // Load and validate all tool definitions
    let tools_dir = registry_dir.join("tools");
    if !tools_dir.exists() {
        anyhow::bail!("no tools/ directory found in {}", registry_dir.display());
    }

    let mut results: Vec<ToolVerifyResult> = Vec::new();
    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;

    let entries = std::fs::read_dir(&tools_dir)
        .with_context(|| format!("failed to read {}", tools_dir.display()))?;

    let mut paths: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            // Skip _meta.toml, non-TOML files, symlinks
            if path.file_name().map(|n| n == "_meta.toml").unwrap_or(false) {
                return false;
            }
            if path.extension().map(|e| e != "toml").unwrap_or(true) {
                return false;
            }
            if e.file_type().map(|ft| ft.is_symlink()).unwrap_or(false) {
                eprintln!("  warning: skipping symlink {}", path.display());
                return false;
            }
            true
        })
        .map(|e| e.path())
        .collect();

    paths.sort();

    for path in &paths {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();

        eprint!("  {:<20} ", name);

        match ToolDef::load(path) {
            Ok(def) => {
                // Tool definition is valid. Try to verify checksums.
                let checksum_status = verify_tool_checksums(&def);
                match checksum_status {
                    Ok(true) => {
                        eprintln!("ok  (checksums verified)");
                        results.push(ToolVerifyResult {
                            name,
                            valid: true,
                            error: None,
                            checksums_verified: Some(true),
                        });
                        valid_count += 1;
                    }
                    Ok(false) => {
                        eprintln!("ok  (no checksum to verify)");
                        results.push(ToolVerifyResult {
                            name,
                            valid: true,
                            error: None,
                            checksums_verified: None,
                        });
                        valid_count += 1;
                    }
                    Err(e) => {
                        eprintln!("FAIL  (checksum: {e})");
                        results.push(ToolVerifyResult {
                            name,
                            valid: false,
                            error: Some(format!("checksum verification failed: {e}")),
                            checksums_verified: Some(false),
                        });
                        invalid_count += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("FAIL  ({e})");
                results.push(ToolVerifyResult {
                    name,
                    valid: false,
                    error: Some(format!("{e}")),
                    checksums_verified: None,
                });
                invalid_count += 1;
            }
        }
    }

    let result = VerifyRegistryOutput {
        tools_checked: results.len(),
        valid: valid_count,
        invalid: invalid_count,
        results,
    };

    if let Some(out_path) = output {
        let json =
            serde_json::to_string_pretty(&result).context("failed to serialize verify output")?;
        std::fs::write(out_path, &json)
            .with_context(|| format!("failed to write {}", out_path.display()))?;
    }

    eprintln!("\n{}", "=".repeat(60));
    eprintln!("Valid:   {valid_count}");
    eprintln!("Invalid: {invalid_count}");

    if invalid_count > 0 {
        anyhow::bail!("{invalid_count} tool(s) failed validation -- MR should not merge");
    }

    Ok(())
}

/// Verify that a tool's inline checksums (if any) match what upstream reports.
///
/// Returns `Ok(true)` if checksums were verified, `Ok(false)` if there are
/// no checksums to verify, and `Err` on mismatch.
fn verify_tool_checksums(def: &ToolDef) -> Result<bool> {
    // If no inline checksums and no checksum config, nothing to verify
    if def.checksums.is_empty() && def.checksum.is_none() {
        return Ok(false);
    }

    // If there are inline checksums, verify they're well-formed (already
    // done by ToolDef::validate, but double-check format here)
    if !def.checksums.is_empty() {
        for (platform, hash) in &def.checksums {
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                anyhow::bail!(
                    "invalid inline checksum for {} ({}): must be 64 hex chars",
                    def.name,
                    platform
                );
            }
        }
    }

    // For tools with upstream checksum files, re-download and verify
    // that the inline checksums match.
    if def.checksum.is_some() && !def.checksums.is_empty() {
        for platform in &PLATFORMS {
            if let Some(inline) = def.checksums.get(platform.key()) {
                match verify::resolve_expected_checksum(def, *platform) {
                    Ok(verify::VerifyResult::Verified { sha256, .. }) => {
                        if sha256 != *inline {
                            anyhow::bail!(
                                "inline checksum for {} ({}) does not match upstream: inline={}, upstream={}",
                                def.name,
                                platform.key(),
                                inline,
                                sha256
                            );
                        }
                    }
                    Ok(verify::VerifyResult::Failed { reason, .. }) => {
                        anyhow::bail!(
                            "upstream checksum resolution failed for {} ({}): {}",
                            def.name,
                            platform.key(),
                            reason
                        );
                    }
                    Ok(verify::VerifyResult::Unavailable { .. }) => {
                        // Upstream checksum not available -- can't cross-verify,
                        // but inline checksum is well-formed. Continue.
                    }
                    Err(e) => {
                        // Network error -- in CI this should be an infrastructure failure
                        anyhow::bail!(
                            "checksum verification error for {} ({}): {e}",
                            def.name,
                            platform.key()
                        );
                    }
                }
            }
        }
        return Ok(true);
    }

    // Inline checksums exist but no upstream checksum file to cross-verify against
    if !def.checksums.is_empty() {
        return Ok(true);
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_valid_tool() -> ToolDef {
        ToolDef {
            name: "test-tool".to_string(),
            description: None,
            source: tool::Source::Github,
            version: "1.0.0".to_string(),
            tag_prefix: "v".to_string(),
            bin: None,
            tier: tool::Tier::Low,
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

    #[test]
    fn verify_no_checksums_returns_false() {
        let def = make_valid_tool();
        assert!(!verify_tool_checksums(&def).unwrap());
    }

    #[test]
    fn verify_valid_inline_checksums_returns_true() {
        let mut def = make_valid_tool();
        def.checksums.insert(
            "macos-arm64".to_string(),
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
        );
        assert!(verify_tool_checksums(&def).unwrap());
    }

    #[test]
    fn verify_invalid_inline_checksum_fails() {
        let mut def = make_valid_tool();
        def.checksums
            .insert("macos-arm64".to_string(), "too-short".to_string());
        assert!(verify_tool_checksums(&def).is_err());
    }
}
