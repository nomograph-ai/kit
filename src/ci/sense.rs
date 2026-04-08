//! Pipeline 1: Sense -- detect upstream changes.
//!
//! Wraps the check phase with sense-specific behavior:
//! - Always succeeds (exit 0) unless infrastructure is broken
//! - Produces sense-report.json with classified findings
//! - Prints a human-readable summary
//!
//! A checksum mismatch on a version bump is expected behavior (old checksum
//! vs new binary). A mismatch on the SAME version would be a supply chain
//! attack, but that case doesn't arise here because sense only runs when a
//! newer version exists.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::tool;

use super::{
    Advisory, BumpLevel, CheckOutput, FindingType, Risk, SenseFinding, SenseReport,
};

/// Classify a version bump as patch, minor, or major.
fn classify_bump(current: &str, new: &str) -> BumpLevel {
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

    let (cm, cmi, _) = parse(current);
    let (am, ami, _) = parse(new);

    if am != cm {
        BumpLevel::Major
    } else if ami != cmi {
        BumpLevel::Minor
    } else {
        BumpLevel::Patch
    }
}

/// Determine risk level from bump magnitude, checksum status, advisories, and tier.
fn classify_risk(
    bump: &BumpLevel,
    checksums_verified: bool,
    has_advisories: bool,
    tier: &str,
) -> Risk {
    if has_advisories {
        return Risk::Critical;
    }
    if !checksums_verified && *bump == BumpLevel::Major {
        return Risk::High;
    }
    if *bump == BumpLevel::Major {
        return Risk::High;
    }
    if !checksums_verified {
        return Risk::Medium;
    }
    if *bump == BumpLevel::Minor && tier == "low" {
        return Risk::Medium;
    }
    Risk::Low
}

/// Run the sense phase: scan all tools and produce a classified report.
///
/// `registry_dir` is the path to the registry root (containing `tools/`).
/// Results are written to `output` as sense-report.json.
///
/// Returns `Ok(())` on all finding conditions. Only returns `Err` on
/// infrastructure failures (cannot read registry, etc.).
pub fn sense(registry_dir: &Path, output: &Path) -> Result<()> {
    // Run the check phase to get raw data
    let tmp_output = tempfile::NamedTempFile::new().context("failed to create temp file")?;
    let tmp_path = tmp_output.path().to_path_buf();

    super::check::check(registry_dir, &tmp_path)?;

    // Read the check output
    let content = std::fs::read_to_string(&tmp_path)
        .with_context(|| format!("failed to read check output from {}", tmp_path.display()))?;
    let check_data: CheckOutput =
        serde_json::from_str(&content).context("failed to parse check output")?;

    // Load tool definitions to get tier information
    let tools = tool::load_registry_tools(registry_dir)?;
    let tier_map: HashMap<String, String> = tools
        .iter()
        .map(|t| (t.name.clone(), t.tier.to_string()))
        .collect();

    // Classify each update into a finding
    let mut findings: Vec<SenseFinding> = Vec::new();

    for update in &check_data.updates {
        let bump = classify_bump(&update.current_version, &update.new_version);

        // All platforms verified = checksums verified
        let checksums_verified = !update.verified.is_empty()
            && update
                .verified
                .values()
                .all(|v| *v == Some(true));

        let tool_advisories: Vec<Advisory> = check_data
            .advisories
            .get(&update.name)
            .cloned()
            .unwrap_or_default();

        let tier = tier_map
            .get(&update.name)
            .cloned()
            .unwrap_or_else(|| "low".to_string());

        let risk = classify_risk(
            &bump,
            checksums_verified,
            !tool_advisories.is_empty(),
            &tier,
        );

        findings.push(SenseFinding {
            tool: update.name.clone(),
            finding_type: if !tool_advisories.is_empty() {
                FindingType::AdvisoryFound
            } else {
                FindingType::VersionBump
            },
            current: update.current_version.clone(),
            available: update.new_version.clone(),
            bump,
            checksums_verified,
            advisories: tool_advisories,
            risk,
            tier,
            note: update.note.clone(),
            checksums: update.checksums.clone(),
            verified: update.verified.clone(),
            tag: update.tag.clone(),
        });
    }

    // Also add advisory-only findings (tools at current version with advisories)
    for (tool_name, advs) in &check_data.advisories {
        // Skip if already covered by a version bump finding
        if findings.iter().any(|f| f.tool == *tool_name) {
            continue;
        }
        let tier = tier_map
            .get(tool_name)
            .cloned()
            .unwrap_or_else(|| "low".to_string());
        let version = tools
            .iter()
            .find(|t| t.name == *tool_name)
            .map(|t| t.version.clone())
            .unwrap_or_default();

        findings.push(SenseFinding {
            tool: tool_name.clone(),
            finding_type: FindingType::AdvisoryFound,
            current: version.clone(),
            available: version,
            bump: BumpLevel::Patch, // no actual bump
            checksums_verified: true,
            advisories: advs.clone(),
            risk: Risk::Critical,
            tier,
            note: Some("advisory on current version -- no version bump available".to_string()),
            checksums: HashMap::new(),
            verified: HashMap::new(),
            tag: String::new(),
        });
    }

    // Infrastructure errors: things that actually prevent the pipeline from working
    let infrastructure_errors: Vec<String> = check_data
        .errors
        .iter()
        .filter(|e| !e.contains("CHECKSUM MISMATCH"))
        .cloned()
        .collect();

    let report = SenseReport {
        findings,
        tools_checked: check_data.tools_checked,
        infrastructure_errors: infrastructure_errors.clone(),
    };

    let json = serde_json::to_string_pretty(&report)
        .context("failed to serialize sense-report.json")?;
    std::fs::write(output, &json)
        .with_context(|| format!("failed to write {}", output.display()))?;

    // Print human-readable summary
    eprintln!("\n{}", "=".repeat(60));
    eprintln!("Sense Report");
    eprintln!("{}", "-".repeat(60));
    eprintln!("Tools checked: {}", report.tools_checked);
    eprintln!("Findings:      {}", report.findings.len());

    if !report.findings.is_empty() {
        eprintln!();
        for f in &report.findings {
            let verified_str = if f.checksums_verified {
                "verified"
            } else {
                "unverified"
            };
            eprintln!(
                "  {:<20} {} -> {:<12} {} bump, {}, risk={}",
                f.tool, f.current, f.available, f.bump, verified_str, f.risk
            );
            for adv in &f.advisories {
                eprintln!(
                    "    ADVISORY: {} ({}) -- {}",
                    adv.id, adv.severity, adv.summary
                );
            }
        }
    }

    if !infrastructure_errors.is_empty() {
        eprintln!();
        eprintln!("Infrastructure errors:");
        for e in &infrastructure_errors {
            eprintln!("  - {e}");
        }
        anyhow::bail!(
            "{} infrastructure error(s) -- pipeline should fail",
            infrastructure_errors.len()
        );
    }

    eprintln!("{}", "=".repeat(60));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_bump_patch() {
        assert_eq!(classify_bump("1.0.0", "1.0.1"), BumpLevel::Patch);
        assert_eq!(classify_bump("2.5.0", "2.5.3"), BumpLevel::Patch);
    }

    #[test]
    fn test_classify_bump_minor() {
        assert_eq!(classify_bump("1.0.0", "1.1.0"), BumpLevel::Minor);
        assert_eq!(classify_bump("1.85.0", "1.86.0"), BumpLevel::Minor);
    }

    #[test]
    fn test_classify_bump_major() {
        assert_eq!(classify_bump("1.0.0", "2.0.0"), BumpLevel::Major);
        assert_eq!(classify_bump("2.5.0", "3.0.6"), BumpLevel::Major);
    }

    #[test]
    fn test_classify_risk_advisory_always_critical() {
        assert_eq!(
            classify_risk(&BumpLevel::Patch, true, true, "own"),
            Risk::Critical
        );
    }

    #[test]
    fn test_classify_risk_major_unverified_high() {
        assert_eq!(
            classify_risk(&BumpLevel::Major, false, false, "high"),
            Risk::High
        );
    }

    #[test]
    fn test_classify_risk_major_verified_high() {
        assert_eq!(
            classify_risk(&BumpLevel::Major, true, false, "high"),
            Risk::High
        );
    }

    #[test]
    fn test_classify_risk_patch_verified_low() {
        assert_eq!(
            classify_risk(&BumpLevel::Patch, true, false, "own"),
            Risk::Low
        );
    }

    #[test]
    fn test_classify_risk_patch_unverified_medium() {
        assert_eq!(
            classify_risk(&BumpLevel::Patch, false, false, "low"),
            Risk::Medium
        );
    }

    #[test]
    fn test_classify_risk_minor_low_tier_medium() {
        assert_eq!(
            classify_risk(&BumpLevel::Minor, true, false, "low"),
            Risk::Medium
        );
    }

    #[test]
    fn test_classify_risk_minor_own_tier_low() {
        assert_eq!(
            classify_risk(&BumpLevel::Minor, true, false, "own"),
            Risk::Low
        );
    }
}
