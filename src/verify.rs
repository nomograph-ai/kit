use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::platform::Platform;
use crate::tool::{ChecksumFormat, SignatureMethod, ToolDef};

/// Outcome of a verification attempt.
#[derive(Debug, Clone)]
pub enum VerifyResult {
    /// Verification passed.
    Verified { method: String, sha256: String },
    /// Verification explicitly failed -- hard stop.
    Failed { method: String, reason: String },
    /// No verification method available -- warning only.
    Unavailable { reason: String },
}

impl VerifyResult {
    #[allow(dead_code)]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    #[allow(dead_code)]
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// Compute the hex-encoded SHA256 digest of a file.
pub fn compute_sha256(path: &Path) -> Result<String> {
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

/// Extract the expected checksum for an asset from a checksum file.
///
/// Returns `Ok(Some(hash))` if found, `Ok(None)` if the asset is not listed.
pub fn parse_checksum_file(
    content: &str,
    asset_name: &str,
    format: &ChecksumFormat,
) -> Result<Option<String>> {
    match format {
        ChecksumFormat::Sha256 => {
            // Lines of `hash  filename` (two-space separator).
            // Match by filename suffix so that `./filename` or path-prefixed entries
            // still match the bare asset name.
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Split on the first run of whitespace (standard sha256sum format
                // uses two spaces, but be tolerant of tabs and single spaces too).
                let mut parts = line.splitn(2, char::is_whitespace);
                let hash = match parts.next() {
                    Some(h) => h.trim(),
                    None => continue,
                };
                let filename = match parts.next() {
                    Some(f) => f.trim().trim_start_matches('*'),
                    None => continue,
                };

                // Match if the filename ends with the asset name (handles ./prefix).
                if filename == asset_name || filename.ends_with(&format!("/{asset_name}")) {
                    validate_hex_hash(hash)?;
                    return Ok(Some(hash.to_lowercase()));
                }
            }
            Ok(None)
        }
        ChecksumFormat::Sha256PerAsset => {
            // The entire content is a single hash (optionally followed by
            // whitespace and a filename). Take the first non-whitespace token.
            let hash = content
                .split_whitespace()
                .next()
                .context("checksum file is empty")?;
            validate_hex_hash(hash)?;
            Ok(Some(hash.to_lowercase()))
        }
    }
}

/// Ensure a string looks like a valid hex-encoded SHA256 hash.
fn validate_hex_hash(h: &str) -> Result<()> {
    if h.len() != 64 {
        anyhow::bail!("expected 64-character SHA256 hash, got {} characters", h.len());
    }
    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("hash contains non-hex characters: {h}");
    }
    Ok(())
}

/// Build an HTTPS-only reqwest blocking client.
fn https_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("failed to build HTTP client")
}

/// F13: Resolve the expected SHA256 for a tool+platform from upstream.
/// Returns the expected hash -- does NOT compare against an actual binary.
/// Callers must compare the result themselves.
/// Checks inline checksums first, falls back to downloading upstream checksum file.
pub fn resolve_expected_checksum(
    tool: &ToolDef,
    platform: Platform,
) -> Result<VerifyResult> {
    // First, check for inline pre-computed checksums.
    let asset_name = match tool.asset_for(platform) {
        Some(a) => a,
        None => {
            return Ok(VerifyResult::Unavailable {
                reason: format!("no asset defined for platform {platform}"),
            });
        }
    };

    // Determine expected hash: prefer inline checksums map, fall back to
    // downloading the upstream checksum file.
    let expected = if let Some(inline) = tool.checksums.get(platform.key()) {
        inline.to_lowercase()
    } else {
        let checksum_url = match tool.checksum_url() {
            Some(u) => u,
            None => {
                return Ok(VerifyResult::Unavailable {
                    reason: "no checksum file configured".to_string(),
                });
            }
        };

        let format = tool
            .checksum
            .as_ref()
            .map(|c| &c.format)
            .unwrap_or(&ChecksumFormat::Sha256);

        let client = https_client()?;
        let resp = client
            .get(&checksum_url)
            .send()
            .with_context(|| format!("failed to download checksum file: {checksum_url}"))?;

        if !resp.status().is_success() {
            return Ok(VerifyResult::Failed {
                method: "sha256".to_string(),
                reason: format!(
                    "checksum file download failed: HTTP {}",
                    resp.status()
                ),
            });
        }

        let body = resp
            .text()
            .context("failed to read checksum file response body")?;

        match parse_checksum_file(&body, &asset_name, format)? {
            Some(h) => h,
            None => {
                return Ok(VerifyResult::Failed {
                    method: "sha256".to_string(),
                    reason: format!(
                        "asset '{asset_name}' not found in checksum file"
                    ),
                });
            }
        }
    };

    Ok(VerifyResult::Verified {
        method: "sha256".to_string(),
        sha256: expected,
    })
}

/// Verify a binary using cosign keyless (sigstore) verification.
///
/// Shells out to `cosign verify-blob` with the bundle downloaded from
/// `bundle_url`. Returns `true` if the signature is valid.
pub fn verify_cosign(
    binary_path: &Path,
    bundle_url: &str,
    issuer: &str,
    identity: &str,
) -> Result<bool> {
    // Download the bundle to a temp file.
    let client = https_client()?;
    let resp = client
        .get(bundle_url)
        .send()
        .with_context(|| format!("failed to download cosign bundle: {bundle_url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "cosign bundle download failed: HTTP {} from {bundle_url}",
            resp.status()
        );
    }
    let bundle_bytes = resp.bytes().context("failed to read bundle body")?;

    let tmp_dir =
        tempfile::tempdir().context("failed to create temp dir for cosign bundle")?;
    let bundle_path = tmp_dir.path().join("bundle.json");
    std::fs::write(&bundle_path, &bundle_bytes)
        .context("failed to write cosign bundle to temp file")?;

    let output = Command::new("cosign")
        .arg("verify-blob")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--certificate-oidc-issuer")
        .arg(issuer)
        .arg("--certificate-identity")
        .arg(identity)
        .arg(binary_path)
        .output()
        .context("failed to execute cosign -- is it installed?")?;

    Ok(output.status.success())
}

/// Verify a binary using GitHub artifact attestation.
///
/// Shells out to `gh attestation verify`. Returns `true` if attestation
/// is valid.
pub fn verify_gh_attestation(binary_path: &Path, repo: &str) -> Result<bool> {
    let output = Command::new("gh")
        .arg("attestation")
        .arg("verify")
        .arg(binary_path)
        .arg("--repo")
        .arg(repo)
        .output()
        .context("failed to execute gh -- is it installed?")?;

    Ok(output.status.success())
}

/// Determine the best verification method from the tool definition and run it.
///
/// Priority order:
///   1. cosign-keyless (sigstore)
///   2. github-attestation (gh attestation verify)
///   3. sha256 checksum
///   4. none (unavailable)
///
/// For methods that also support checksums, we compute and include the sha256
/// of the installed binary in the result regardless.
pub fn verify_tool(
    tool: &ToolDef,
    platform: Platform,
    mise_install_dir: &Path,
) -> Result<VerifyResult> {
    let bin_name = tool.bin_name();
    let binary_path = mise_install_dir.join("bin").join(bin_name);

    if !binary_path.exists() {
        return Ok(VerifyResult::Failed {
            method: "pre-check".to_string(),
            reason: format!("binary not found at {}", binary_path.display()),
        });
    }

    // Always compute the installed binary's SHA256 for the result.
    let actual_sha = compute_sha256(&binary_path)?;

    // -- 1. Cosign keyless --
    if let Some(ref sig) = tool.signature
        && sig.method == SignatureMethod::CosignKeyless
    {
            let issuer = sig
                .issuer
                .as_deref()
                .context("cosign-keyless requires 'issuer' in signature config")?;
            let identity = sig
                .identity
                .as_deref()
                .context("cosign-keyless requires 'identity' in signature config")?;

            // Construct the bundle URL (same base as the binary, with .bundle suffix).
            let asset_name = tool
                .asset_for(platform)
                .context("no asset for platform")?;
            let bundle_asset = format!("{asset_name}.bundle");
            let bundle_url = tool
                .url_for(platform)
                .map(|u| {
                    // Replace the asset filename with the bundle filename.
                    u.replace(&asset_name, &bundle_asset)
                })
                .context("cannot determine bundle URL")?;

            match verify_cosign(&binary_path, &bundle_url, issuer, identity) {
                Ok(true) => {
                    // Cosign passed; still verify checksum if available.
                    let checksum_result = verify_checksum_against_binary(tool, platform, &actual_sha);
                    if let Some(VerifyResult::Failed { method, reason }) = checksum_result {
                        return Ok(VerifyResult::Failed {
                            method: format!("cosign-keyless+{method}"),
                            reason,
                        });
                    }
                    return Ok(VerifyResult::Verified {
                        method: "cosign-keyless".to_string(),
                        sha256: actual_sha,
                    });
                }
                Ok(false) => {
                    return Ok(VerifyResult::Failed {
                        method: "cosign-keyless".to_string(),
                        reason: "cosign verify-blob returned non-zero".to_string(),
                    });
                }
                Err(e) => {
                    // cosign not installed or other execution error -- fall through
                    eprintln!(
                        "  warning: cosign verification failed ({e:#}), falling back"
                    );
                }
            }
    }

    // -- 2. GitHub attestation --
    if let Some(ref sig) = tool.signature
        && sig.method == SignatureMethod::GithubAttestation
    {
            let repo = tool
                .repo
                .as_deref()
                .context("github-attestation requires 'repo' on tool definition")?;

            match verify_gh_attestation(&binary_path, repo) {
                Ok(true) => {
                    let checksum_result = verify_checksum_against_binary(tool, platform, &actual_sha);
                    if let Some(VerifyResult::Failed { method, reason }) = checksum_result {
                        return Ok(VerifyResult::Failed {
                            method: format!("github-attestation+{method}"),
                            reason,
                        });
                    }
                    return Ok(VerifyResult::Verified {
                        method: "github-attestation".to_string(),
                        sha256: actual_sha,
                    });
                }
                Ok(false) => {
                    return Ok(VerifyResult::Failed {
                        method: "github-attestation".to_string(),
                        reason: "gh attestation verify returned non-zero".to_string(),
                    });
                }
                Err(e) => {
                    eprintln!(
                        "  warning: gh attestation check failed ({e:#}), falling back"
                    );
                }
            }
    }

    // -- 3. SHA256 checksum --
    if tool.checksum.is_some() || !tool.checksums.is_empty() {
        let checksum_result = resolve_expected_checksum(tool, platform)?;
        match checksum_result {
            VerifyResult::Verified {
                method,
                sha256: expected,
            } => {
                if actual_sha == expected {
                    return Ok(VerifyResult::Verified {
                        method,
                        sha256: actual_sha,
                    });
                } else {
                    return Ok(VerifyResult::Failed {
                        method,
                        reason: format!(
                            "checksum mismatch: expected {expected}, got {actual_sha}"
                        ),
                    });
                }
            }
            other => return Ok(other),
        }
    }

    // -- 4. Nothing available --
    Ok(VerifyResult::Unavailable {
        reason: "no checksum or signature method configured".to_string(),
    })
}

/// Helper: verify a checksum against an already-computed binary hash.
/// Returns `Some(VerifyResult::Failed)` on mismatch, `None` on match or
/// if no checksum is configured.
fn verify_checksum_against_binary(
    tool: &ToolDef,
    platform: Platform,
    actual_sha: &str,
) -> Option<VerifyResult> {
    if tool.checksum.is_none() && tool.checksums.is_empty() {
        return None;
    }
    match resolve_expected_checksum(tool, platform) {
        Ok(VerifyResult::Verified { sha256: expected, .. }) => {
            if actual_sha != expected {
                Some(VerifyResult::Failed {
                    method: "sha256".to_string(),
                    reason: format!(
                        "checksum mismatch: expected {expected}, got {actual_sha}"
                    ),
                })
            } else {
                None
            }
        }
        Ok(VerifyResult::Failed { method, reason }) => Some(VerifyResult::Failed { method, reason }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sha256_known_data() {
        // SHA256 of "hello\n" (echo "hello") is well-known.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"hello\n").unwrap();
        }
        let hash = compute_sha256(&path).unwrap();
        assert_eq!(
            hash,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }

    #[test]
    fn sha256_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty");
        std::fs::File::create(&path).unwrap();
        let hash = compute_sha256(&path).unwrap();
        // SHA256 of empty input.
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parse_checksum_sha256_standard() {
        let content = "\
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  gh_2.89.0_macOS_arm64.zip
1111111111111111111111111111111111111111111111111111111111111111  gh_2.89.0_linux_amd64.tar.gz
";
        let result = parse_checksum_file(
            content,
            "gh_2.89.0_macOS_arm64.zip",
            &ChecksumFormat::Sha256,
        )
        .unwrap();
        assert_eq!(
            result,
            Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string())
        );
    }

    #[test]
    fn parse_checksum_sha256_not_found() {
        let content = "\
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  other-file.tar.gz
";
        let result = parse_checksum_file(
            content,
            "missing-asset.zip",
            &ChecksumFormat::Sha256,
        )
        .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn parse_checksum_sha256_per_asset() {
        let content =
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n";
        let result = parse_checksum_file(
            content,
            "anything.tar.gz",
            &ChecksumFormat::Sha256PerAsset,
        )
        .unwrap();
        assert_eq!(
            result,
            Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string())
        );
    }

    #[test]
    fn parse_checksum_sha256_per_asset_with_filename() {
        let content =
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  muxr-darwin-arm64\n";
        let result = parse_checksum_file(
            content,
            "muxr-darwin-arm64",
            &ChecksumFormat::Sha256PerAsset,
        )
        .unwrap();
        assert_eq!(
            result,
            Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string())
        );
    }

    #[test]
    fn parse_checksum_rejects_bad_hash() {
        // Too short.
        let content = "deadbeef  some-file.tar.gz\n";
        let result =
            parse_checksum_file(content, "some-file.tar.gz", &ChecksumFormat::Sha256);
        assert!(result.is_err());
    }

    #[test]
    fn parse_checksum_skips_comments() {
        let content = "\
# This is a comment
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  target.bin
";
        let result = parse_checksum_file(
            content,
            "target.bin",
            &ChecksumFormat::Sha256,
        )
        .unwrap();
        assert_eq!(
            result,
            Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string())
        );
    }

    #[test]
    fn checksum_mismatch_detection() {
        // Simulate: expected vs actual differ.
        let expected = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let actual = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_ne!(expected, actual);

        // Create a file whose hash will not match the "expected" value.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"some binary content").unwrap();
        }
        let actual_hash = compute_sha256(&path).unwrap();
        assert_ne!(actual_hash, expected, "hash should not match fabricated expected value");
    }

    #[test]
    fn validate_hex_hash_accepts_valid() {
        let valid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(validate_hex_hash(valid).is_ok());
    }

    #[test]
    fn validate_hex_hash_rejects_short() {
        assert!(validate_hex_hash("abc123").is_err());
    }

    #[test]
    fn validate_hex_hash_rejects_non_hex() {
        let bad = "zzzz23d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(validate_hex_hash(bad).is_err());
    }
}
