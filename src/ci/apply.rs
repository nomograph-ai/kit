//! Phase 3: Apply evaluated updates to registry TOML files.
//!
//! Reads evaluated.json from Phase 2. For approved updates:
//! 1. Load the tool's TOML file from tools/<name>.toml
//! 2. Update version and inline checksums using toml_edit (preserve formatting)
//! 3. Write the file back
//! 4. Output apply-result.json for CI to consume
//!
//! This module is pure: it modifies files on disk and writes JSON.
//! It does NOT create git branches, commits, MRs, or call any external APIs.
//! The CI pipeline component owns all git/MR lifecycle.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use super::sense::classify_bump;
use super::{AppliedUpdate, ApplyGroup, ApplyOutput, EvaluateOutput};
use crate::tool::{self, Tier, ToolDef};

/// Run the apply phase.
///
/// Reads `input` (evaluated.json), applies approved updates to the
/// tool TOML files in the current working directory, then writes
/// `output` (apply-result.json) with everything CI needs to create
/// the branch, MR, and optionally auto-merge.
pub fn apply(input: &Path, output: &Path) -> Result<()> {
    let content = std::fs::read_to_string(input)
        .with_context(|| format!("failed to read {}", input.display()))?;
    let data: EvaluateOutput =
        serde_json::from_str(&content).context("failed to parse evaluated.json")?;

    // Partition by evaluation
    let to_apply: Vec<_> = data
        .evaluated
        .iter()
        .filter(|e| e.evaluation == "auto-approved" || e.evaluation == "approve")
        .collect();

    let flagged: Vec<_> = data
        .evaluated
        .iter()
        .filter(|e| e.evaluation == "flag")
        .collect();

    let rejected: Vec<_> = data
        .evaluated
        .iter()
        .filter(|e| e.evaluation == "reject")
        .collect();

    // Apply approved AND flagged updates -- the MR is the review surface.
    // Only rejected items (actual supply chain risk) are excluded.
    let all_to_apply: Vec<_> = to_apply.iter().chain(flagged.iter()).collect();

    eprintln!(
        "kit apply: {} updates to apply ({} approved, {} flagged for review)",
        all_to_apply.len(),
        to_apply.len(),
        flagged.len()
    );
    if !rejected.is_empty() {
        eprintln!("  rejected (excluded): {}", rejected.len());
    }

    if all_to_apply.is_empty() {
        eprintln!("Nothing to apply");
        let result = ApplyOutput {
            auto_merge_group: None,
            review_group: None,
            rejected_names: rejected.iter().map(|r| r.candidate.name.clone()).collect(),
            flagged_names: vec![],
        };
        let json = serde_json::to_string_pretty(&result)?;
        std::fs::write(output, &json)
            .with_context(|| format!("failed to write {}", output.display()))?;
        return Ok(());
    }

    // Load registry policy for auto-merge decisions
    let policy = match tool::load_registry_meta(Path::new(".")) {
        Ok(meta) => meta.policy,
        Err(e) => {
            eprintln!("  warning: could not load _meta.toml policy ({e}), auto-merge disabled");
            tool::RegistryPolicy::default()
        }
    };

    // Apply each update to its TOML file
    let mut applied: Vec<AppliedUpdate> = Vec::new();

    for update in &all_to_apply {
        let name = &update.candidate.name;
        let old_version = &update.candidate.current_version;
        let new_version = &update.candidate.new_version;
        let tool_path = Path::new("tools").join(format!("{name}.toml"));

        if !tool_path.exists() {
            eprintln!("  warning: {name}.toml not found, skipping");
            continue;
        }

        eprintln!("  applying {name}: {old_version} -> {new_version}");

        // Load tool definition to get tier
        let tier = match ToolDef::load(&tool_path) {
            Ok(def) => def.tier,
            Err(_) => Tier::Low, // default if we can't parse
        };

        // Use toml_edit for surgical updates that preserve formatting
        let raw = std::fs::read_to_string(&tool_path)
            .with_context(|| format!("failed to read {}", tool_path.display()))?;

        let updated = update_tool_toml(&raw, new_version, &update.candidate.checksums)
            .with_context(|| format!("failed to update {}", tool_path.display()))?;

        match updated {
            Some(new_content) => {
                std::fs::write(&tool_path, new_content)
                    .with_context(|| format!("failed to write {}", tool_path.display()))?;
            }
            None => {
                eprintln!("  warning: no [tool] table in {name}.toml, skipping");
                continue;
            }
        }

        let bump = classify_bump(old_version, new_version);
        let checksums_verified = update.candidate.verified.values().all(|v| *v == Some(true))
            && !update.candidate.verified.is_empty();

        applied.push(AppliedUpdate {
            name: name.clone(),
            old_version: old_version.clone(),
            new_version: new_version.clone(),
            file: format!("tools/{name}.toml"),
            evaluation: update.evaluation.clone(),
            bump: bump.to_string(),
            tier: tier.to_string(),
            checksums_verified,
            eval_reason: update.eval_reason.clone(),
            review_reasons: update.review_reasons.clone(),
        });
    }

    if applied.is_empty() {
        eprintln!("No files were modified");
        let result = ApplyOutput {
            auto_merge_group: None,
            review_group: None,
            rejected_names: rejected.iter().map(|r| r.candidate.name.clone()).collect(),
            flagged_names: flagged.iter().map(|f| f.candidate.name.clone()).collect(),
        };
        let json = serde_json::to_string_pretty(&result)?;
        std::fs::write(output, &json)
            .with_context(|| format!("failed to write {}", output.display()))?;
        return Ok(());
    }

    // Partition applied updates by auto-merge eligibility
    let (auto_eligible, review_needed): (Vec<AppliedUpdate>, Vec<AppliedUpdate>) =
        applied.into_iter().partition(|u| {
            let tier = match u.tier.as_str() {
                "own" => Tier::Own,
                "high" => Tier::High,
                _ => Tier::Low,
            };
            u.evaluation != "flag"
                && policy.is_auto_merge_eligible(tier, &u.bump, u.checksums_verified)
        });

    // Build groups
    let now = chrono::Utc::now();
    let timestamp = now.format("%Y%m%d-%H%M%S").to_string();
    let today = now.format("%Y-%m-%d").to_string();

    let auto_merge_group = if auto_eligible.is_empty() {
        None
    } else {
        let mr_body = build_mr_body_for_group("Auto-Merge Updates", &auto_eligible, &rejected);
        Some(ApplyGroup {
            branch_hint: format!("kit/auto-{timestamp}"),
            commit_message: build_commit_message(&today, &auto_eligible),
            mr_title: format!("kit: auto-merge updates {today}"),
            mr_body,
            auto_merge_eligible: true,
            applied: auto_eligible,
        })
    };

    let review_group = if review_needed.is_empty() {
        None
    } else {
        let mr_body = build_mr_body_for_group("Review Required", &review_needed, &rejected);
        Some(ApplyGroup {
            branch_hint: format!("kit/review-{timestamp}"),
            commit_message: build_commit_message(&today, &review_needed),
            mr_title: format!("kit: tool updates {today} (review)"),
            mr_body,
            auto_merge_eligible: false,
            applied: review_needed,
        })
    };

    let flagged_names = flagged.iter().map(|f| f.candidate.name.clone()).collect();
    let rejected_names = rejected.iter().map(|r| r.candidate.name.clone()).collect();

    let result = ApplyOutput {
        auto_merge_group,
        review_group,
        rejected_names,
        flagged_names,
    };

    let json =
        serde_json::to_string_pretty(&result).context("failed to serialize apply-result.json")?;
    std::fs::write(output, &json)
        .with_context(|| format!("failed to write {}", output.display()))?;

    eprintln!("\n{}", "=".repeat(60));
    if let Some(ref g) = result.auto_merge_group {
        eprintln!("Auto-merge ({}):", g.applied.len());
        for u in &g.applied {
            eprintln!("  {}: {} -> {}", u.name, u.old_version, u.new_version);
        }
    }
    if let Some(ref g) = result.review_group {
        eprintln!("Review needed ({}):", g.applied.len());
        for u in &g.applied {
            eprintln!("  {}: {} -> {}", u.name, u.old_version, u.new_version);
        }
    }

    Ok(())
}

/// Build the commit message for CI to use.
fn build_commit_message(today: &str, applied: &[AppliedUpdate]) -> String {
    let mut lines = vec![format!("kit: tool updates {today}")];
    lines.push(String::new());
    for u in applied {
        lines.push(format!(
            "- {}: {} -> {}",
            u.name, u.old_version, u.new_version
        ));
    }
    lines.push(String::new());
    lines.push("AI-Assisted: yes".to_string());
    lines.push("AI-Tools: kit CI".to_string());
    lines.join("\n")
}

/// Build the MR description body for a single group.
fn build_mr_body_for_group(
    heading: &str,
    applied: &[AppliedUpdate],
    rejected: &[&super::EvaluatedUpdate],
) -> String {
    let mut body = format!("## {heading}\n\n");

    body.push_str("| Tool | Version | Tier | Bump | Checksums |\n");
    body.push_str("|------|---------|------|------|-----------|\n");
    for u in applied {
        let checksum_label = if u.checksums_verified {
            "verified"
        } else {
            "unverified"
        };
        body.push_str(&format!(
            "| **{}** | {} -> {} | {} | {} | {} |\n",
            u.name, u.old_version, u.new_version, u.tier, u.bump, checksum_label,
        ));
    }
    body.push('\n');

    // Include eval reasons for flagged or reviewed items
    let has_reasons = applied
        .iter()
        .any(|u| u.eval_reason.is_some() || !u.review_reasons.is_empty());
    if has_reasons {
        body.push_str("<details>\n<summary>Review details</summary>\n\n");
        for u in applied {
            if u.eval_reason.is_some() || !u.review_reasons.is_empty() {
                body.push_str(&format!("**{}**\n", u.name));
                for reason in &u.review_reasons {
                    body.push_str(&format!("- {reason}\n"));
                }
                if let Some(ref eval) = u.eval_reason {
                    body.push_str(&format!("- Assessment: {eval}\n"));
                }
                body.push('\n');
            }
        }
        body.push_str("</details>\n\n");
    }

    if !rejected.is_empty() {
        body.push_str("### Rejected\n\n");
        body.push_str("| Tool | Version | Reason |\n");
        body.push_str("|------|---------|--------|\n");
        for r in rejected {
            body.push_str(&format!(
                "| **{}** | {} -> {} | {} |\n",
                r.candidate.name,
                r.candidate.current_version,
                r.candidate.new_version,
                r.eval_reason.as_deref().unwrap_or("rejected")
            ));
        }
        body.push('\n');
    }

    body.push_str("\n---\n*Generated by kit CI (sense/respond/verify pipeline)*\n");
    body
}

/// Update a tool TOML string with a new version and checksums.
///
/// Returns `Some(new_content)` on success, or `None` if the TOML has no
/// `[tool]` table.
fn update_tool_toml(
    raw: &str,
    new_version: &str,
    checksums: &HashMap<String, Option<String>>,
) -> Result<Option<String>> {
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .context("failed to parse TOML")?;

    let tool_table = match doc.get_mut("tool").and_then(|t| t.as_table_mut()) {
        Some(t) => t,
        None => return Ok(None),
    };

    tool_table["version"] = toml_edit::value(new_version);

    // Update inline checksums from the check phase.
    // Filter to only platforms that have a computed hash (Some).
    let new_hashes: Vec<_> = checksums
        .iter()
        .filter_map(|(platform, sha)| sha.as_ref().map(|hash| (platform.as_str(), hash.as_str())))
        .collect();

    if !new_hashes.is_empty() {
        // Create the [tool.checksums] table if it doesn't exist yet.
        if tool_table.get("checksums").is_none() {
            tool_table.insert("checksums", toml_edit::Item::Table(toml_edit::Table::new()));
        }

        if let Some(checksums_table) = tool_table
            .get_mut("checksums")
            .and_then(|t| t.as_table_mut())
        {
            for (platform, hash) in &new_hashes {
                checksums_table[*platform] = toml_edit::value(*hash);
            }
        }
    }

    Ok(Some(doc.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_version_and_existing_checksums() {
        let input = r#"[tool]
name = "muxr"
version = "0.6.0"

[tool.checksums]
macos-arm64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
linux-x64 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#;

        let checksums = HashMap::from([
            (
                "macos-arm64".to_string(),
                Some(
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
                ),
            ),
            (
                "linux-x64".to_string(),
                Some(
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
                ),
            ),
        ]);

        let result = update_tool_toml(input, "0.7.0", &checksums)
            .unwrap()
            .unwrap();

        assert!(
            result.contains("version = \"0.7.0\""),
            "version should be updated"
        );
        assert!(
            result.contains("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            "macos checksum should be updated"
        );
        assert!(
            !result.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "old macos checksum should be replaced"
        );
    }

    #[test]
    fn create_checksums_table_when_missing() {
        let input = r#"[tool]
name = "muxr"
version = "0.6.0"
source = "gitlab"
"#;

        let checksums = HashMap::from([(
            "macos-arm64".to_string(),
            Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string()),
        )]);

        let result = update_tool_toml(input, "0.7.0", &checksums)
            .unwrap()
            .unwrap();

        assert!(
            result.contains("version = \"0.7.0\""),
            "version should be updated"
        );
        assert!(
            result.contains("[tool.checksums]"),
            "checksums table should be created"
        );
        assert!(
            result.contains("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            "checksum should be written"
        );
    }

    #[test]
    fn skip_checksums_when_empty() {
        let input = r#"[tool]
name = "claude-code"
version = "1.0.0"
source = "npm"
"#;

        let checksums = HashMap::new();

        let result = update_tool_toml(input, "1.1.0", &checksums)
            .unwrap()
            .unwrap();

        assert!(
            result.contains("version = \"1.1.0\""),
            "version should be updated"
        );
        assert!(
            !result.contains("checksums"),
            "no checksums table should be created when map is empty"
        );
    }

    #[test]
    fn skip_none_checksums() {
        let input = r#"[tool]
name = "test"
version = "1.0.0"
"#;

        // Only None values -- download failed for all platforms
        let checksums = HashMap::from([
            ("macos-arm64".to_string(), None),
            ("linux-x64".to_string(), None),
        ]);

        let result = update_tool_toml(input, "1.1.0", &checksums)
            .unwrap()
            .unwrap();

        assert!(
            result.contains("version = \"1.1.0\""),
            "version should be updated"
        );
        assert!(
            !result.contains("checksums"),
            "no checksums table when all values are None"
        );
    }

    #[test]
    fn returns_none_without_tool_table() {
        let input = r#"[something]
key = "value"
"#;

        let result = update_tool_toml(input, "1.0.0", &HashMap::new()).unwrap();
        assert!(result.is_none(), "should return None without [tool] table");
    }

    // -- Partition logic tests --

    fn make_update(name: &str, tier: &str, bump: &str, checksums_verified: bool) -> AppliedUpdate {
        AppliedUpdate {
            name: name.to_string(),
            old_version: "1.0.0".to_string(),
            new_version: "1.0.1".to_string(),
            file: format!("tools/{name}.toml"),
            evaluation: "auto-approved".to_string(),
            bump: bump.to_string(),
            tier: tier.to_string(),
            checksums_verified,
            eval_reason: None,
            review_reasons: vec![],
        }
    }

    #[test]
    fn partition_mixed_batch_splits_by_eligibility() {
        use crate::tool::{RegistryPolicy, Tier};

        let policy = RegistryPolicy {
            auto_merge_tiers: vec![Tier::Low],
            auto_merge_bump: vec!["patch".to_string(), "minor".to_string()],
            auto_merge_requires_checksum: true,
        };

        let updates = vec![
            make_update("uv", "low", "patch", true),
            make_update("yq", "low", "minor", true),
            make_update("glab", "high", "minor", true),
            make_update("rune", "own", "minor", true),
        ];

        let (auto_eligible, review_needed): (Vec<_>, Vec<_>) = updates.into_iter().partition(|u| {
            let tier = match u.tier.as_str() {
                "own" => Tier::Own,
                "high" => Tier::High,
                _ => Tier::Low,
            };
            u.evaluation != "flag"
                && policy.is_auto_merge_eligible(tier, &u.bump, u.checksums_verified)
        });

        assert_eq!(auto_eligible.len(), 2, "uv and yq should auto-merge");
        assert_eq!(review_needed.len(), 2, "glab and rune need review");
        assert!(auto_eligible.iter().all(|u| u.tier == "low"));
        assert!(review_needed.iter().any(|u| u.tier == "high"));
        assert!(review_needed.iter().any(|u| u.tier == "own"));
    }

    #[test]
    fn partition_all_low_tier_puts_everything_in_auto() {
        use crate::tool::{RegistryPolicy, Tier};

        let policy = RegistryPolicy {
            auto_merge_tiers: vec![Tier::Low],
            auto_merge_bump: vec!["patch".to_string(), "minor".to_string()],
            auto_merge_requires_checksum: true,
        };

        let updates = vec![
            make_update("uv", "low", "patch", true),
            make_update("yq", "low", "minor", true),
            make_update("glow", "low", "patch", true),
        ];

        let (auto_eligible, review_needed): (Vec<_>, Vec<_>) = updates.into_iter().partition(|u| {
            let tier = match u.tier.as_str() {
                "own" => Tier::Own,
                "high" => Tier::High,
                _ => Tier::Low,
            };
            u.evaluation != "flag"
                && policy.is_auto_merge_eligible(tier, &u.bump, u.checksums_verified)
        });

        assert_eq!(auto_eligible.len(), 3);
        assert!(review_needed.is_empty());
    }

    #[test]
    fn partition_unverified_checksum_goes_to_review() {
        use crate::tool::{RegistryPolicy, Tier};

        let policy = RegistryPolicy {
            auto_merge_tiers: vec![Tier::Low],
            auto_merge_bump: vec!["patch".to_string()],
            auto_merge_requires_checksum: true,
        };

        let updates = vec![
            make_update("uv", "low", "patch", true),
            make_update("dolt", "low", "patch", false), // no checksums
        ];

        let (auto_eligible, review_needed): (Vec<_>, Vec<_>) = updates.into_iter().partition(|u| {
            let tier = match u.tier.as_str() {
                "own" => Tier::Own,
                "high" => Tier::High,
                _ => Tier::Low,
            };
            u.evaluation != "flag"
                && policy.is_auto_merge_eligible(tier, &u.bump, u.checksums_verified)
        });

        assert_eq!(auto_eligible.len(), 1, "uv should auto-merge");
        assert_eq!(auto_eligible[0].name, "uv");
        assert_eq!(review_needed.len(), 1, "dolt needs review");
        assert_eq!(review_needed[0].name, "dolt");
    }

    #[test]
    fn partition_flagged_evaluation_goes_to_review() {
        use crate::tool::{RegistryPolicy, Tier};

        let policy = RegistryPolicy {
            auto_merge_tiers: vec![Tier::Low],
            auto_merge_bump: vec!["patch".to_string()],
            auto_merge_requires_checksum: true,
        };

        let mut flagged = make_update("hugo", "low", "patch", true);
        flagged.evaluation = "flag".to_string();

        let updates = vec![make_update("uv", "low", "patch", true), flagged];

        let (auto_eligible, review_needed): (Vec<_>, Vec<_>) = updates.into_iter().partition(|u| {
            let tier = match u.tier.as_str() {
                "own" => Tier::Own,
                "high" => Tier::High,
                _ => Tier::Low,
            };
            u.evaluation != "flag"
                && policy.is_auto_merge_eligible(tier, &u.bump, u.checksums_verified)
        });

        assert_eq!(auto_eligible.len(), 1);
        assert_eq!(review_needed.len(), 1);
        assert_eq!(review_needed[0].name, "hugo");
    }

    // -- TOML manipulation tests --

    #[test]
    fn preserves_formatting_and_other_fields() {
        let input = r#"[tool]
name = "gh"
description = "GitHub CLI"
version = "2.89.0"
source = "github"
repo = "cli/cli"
tier = "high"

[tool.checksums]
macos-arm64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;

        let checksums = HashMap::from([(
            "macos-arm64".to_string(),
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()),
        )]);

        let result = update_tool_toml(input, "2.90.0", &checksums)
            .unwrap()
            .unwrap();

        assert!(result.contains("name = \"gh\""), "name preserved");
        assert!(
            result.contains("description = \"GitHub CLI\""),
            "description preserved"
        );
        assert!(result.contains("source = \"github\""), "source preserved");
        assert!(result.contains("repo = \"cli/cli\""), "repo preserved");
        assert!(result.contains("tier = \"high\""), "tier preserved");
        assert!(result.contains("version = \"2.90.0\""), "version updated");
        assert!(
            result.contains("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            "checksum updated"
        );
    }
}
