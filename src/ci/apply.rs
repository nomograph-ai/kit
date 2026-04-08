//! Phase 3: Apply evaluated updates to registry TOML files.
//!
//! Reads evaluated.json from Phase 2. For approved updates:
//! 1. Load the tool's TOML file from tools/<name>.toml
//! 2. Update version and inline checksums using toml_edit (preserve formatting)
//! 3. Write the file back
//! 4. Git add, commit, push to a new branch
//! 5. Create MR via glab CLI

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use super::EvaluateOutput;

/// Run the apply phase.
///
/// Reads `input` (evaluated.json), applies approved updates to the
/// tool TOML files in the current working directory, then creates
/// a branch and MR.
pub fn apply(input: &Path) -> Result<()> {
    let content = std::fs::read_to_string(input)
        .with_context(|| format!("failed to read {}", input.display()))?;
    let data: EvaluateOutput =
        serde_json::from_str(&content).context("failed to parse evaluated.json")?;

    // Filter to approved updates
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

    eprintln!("kit apply: {} approved updates", to_apply.len());
    if !flagged.is_empty() {
        eprintln!("  flagged for review: {}", flagged.len());
    }
    if !rejected.is_empty() {
        eprintln!("  rejected: {}", rejected.len());
    }

    if to_apply.is_empty() && flagged.is_empty() {
        eprintln!("Nothing to apply or flag");
        return Ok(());
    }

    // Apply each approved update to its TOML file
    let mut applied_names: Vec<String> = Vec::new();

    for update in &to_apply {
        let name = &update.candidate.name;
        let old_version = &update.candidate.current_version;
        let new_version = &update.candidate.new_version;
        let tool_path = Path::new("tools").join(format!("{name}.toml"));

        if !tool_path.exists() {
            eprintln!("  warning: {name}.toml not found, skipping");
            continue;
        }

        eprintln!("  applying {name}: {old_version} -> {new_version}");

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

        applied_names.push(name.clone());
    }

    if applied_names.is_empty() {
        eprintln!("No files were modified");
        return Ok(());
    }

    // Create branch, commit, push, create MR
    let now = chrono::Utc::now();
    let branch = format!("kit/update-{}", now.format("%Y%m%d-%H%M"));
    let today = now.format("%Y-%m-%d").to_string();

    // Create and switch to the branch
    run_git(&["checkout", "-b", &branch])?;

    // Stage all modified tool files
    for name in &applied_names {
        let path = format!("tools/{name}.toml");
        run_git(&["add", &path])?;
    }

    // Build commit message
    let mut commit_lines = vec![format!("kit: tool updates {today}")];
    commit_lines.push(String::new());
    for update in &to_apply {
        if applied_names.contains(&update.candidate.name) {
            commit_lines.push(format!(
                "- {}: {} -> {}",
                update.candidate.name,
                update.candidate.current_version,
                update.candidate.new_version
            ));
        }
    }
    commit_lines.push(String::new());
    commit_lines.push("AI-Assisted: yes".to_string());
    commit_lines.push("AI-Tools: kit CI".to_string());

    let commit_msg = commit_lines.join("\n");
    run_git(&["commit", "-m", &commit_msg])?;

    // Push the branch
    run_git(&["push", "-u", "origin", &branch])?;

    // Build MR description -- full audit trail
    let mut mr_body = String::from("## Tool Updates\n\n");

    if !to_apply.is_empty() {
        mr_body.push_str("### Approved\n\n");
        mr_body.push_str("| Tool | Version | Checksum | Evaluation |\n");
        mr_body.push_str("|------|---------|----------|------------|\n");
        for update in &to_apply {
            if applied_names.contains(&update.candidate.name) {
                let checksum_status = format_checksum_status(&update.candidate);
                mr_body.push_str(&format!(
                    "| **{}** | {} -> {} | {} | {} |\n",
                    update.candidate.name,
                    update.candidate.current_version,
                    update.candidate.new_version,
                    checksum_status,
                    update.evaluation,
                ));
            }
        }
        mr_body.push('\n');

        // Detail section with reasoning
        mr_body.push_str("<details>\n<summary>Approval details</summary>\n\n");
        for update in &to_apply {
            if applied_names.contains(&update.candidate.name) {
                mr_body.push_str(&format!("**{}**\n", update.candidate.name));
                if let Some(ref reason) = update.eval_reason {
                    mr_body.push_str(&format!("- Reason: {reason}\n"));
                }
                if let Some(ref note) = update.candidate.note {
                    mr_body.push_str(&format!("- Note: {note}\n"));
                }
                // Checksum detail per platform
                for (platform, verified) in &update.candidate.verified {
                    let status = match verified {
                        Some(true) => "verified",
                        Some(false) => "MISMATCH",
                        None => "unavailable",
                    };
                    mr_body.push_str(&format!("- {platform}: {status}\n"));
                }
                mr_body.push('\n');
            }
        }
        mr_body.push_str("</details>\n\n");
    }

    if !flagged.is_empty() {
        mr_body.push_str("### Flagged for Review\n\n");
        mr_body.push_str("| Tool | Version | Reason |\n");
        mr_body.push_str("|------|---------|--------|\n");
        for f in &flagged {
            mr_body.push_str(&format!(
                "| **{}** | {} -> {} | {} |\n",
                f.candidate.name,
                f.candidate.current_version,
                f.candidate.new_version,
                f.eval_reason.as_deref().unwrap_or("needs review")
            ));
        }
        mr_body.push('\n');

        if flagged.iter().any(|f| !f.review_reasons.is_empty()) {
            mr_body.push_str("<details>\n<summary>Review details</summary>\n\n");
            for f in &flagged {
                mr_body.push_str(&format!("**{}**\n", f.candidate.name));
                for reason in &f.review_reasons {
                    mr_body.push_str(&format!("- {reason}\n"));
                }
                if let Some(ref eval) = f.eval_reason {
                    mr_body.push_str(&format!("- LLM assessment: {eval}\n"));
                }
                mr_body.push('\n');
            }
            mr_body.push_str("</details>\n\n");
        }
    }

    if !rejected.is_empty() {
        mr_body.push_str("### Rejected\n\n");
        mr_body.push_str("| Tool | Version | Reason |\n");
        mr_body.push_str("|------|---------|--------|\n");
        for r in &rejected {
            mr_body.push_str(&format!(
                "| **{}** | {} -> {} | {} |\n",
                r.candidate.name,
                r.candidate.current_version,
                r.candidate.new_version,
                r.eval_reason.as_deref().unwrap_or("rejected")
            ));
        }
        mr_body.push('\n');
    }

    mr_body.push_str("\n---\n*Generated by kit CI (sense/respond/verify pipeline)*\n");

    // Create MR -- try glab first, fall back to API via CI_JOB_TOKEN
    let mr_title = format!("kit: tool updates {today}");

    let glab_ok = Command::new("glab")
        .args([
            "mr",
            "create",
            "--title",
            &mr_title,
            "--description",
            &mr_body,
            "--source-branch",
            &branch,
            "--remove-source-branch",
            "--yes",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !glab_ok {
        // Fallback: create MR via API using CI_JOB_TOKEN (works in CI without GITLAB_TOKEN)
        if let (Ok(api_url), Ok(project_id), Ok(token)) = (
            std::env::var("CI_API_V4_URL"),
            std::env::var("CI_PROJECT_ID"),
            std::env::var("CI_JOB_TOKEN"),
        ) {
            let mr_json = serde_json::json!({
                "source_branch": branch,
                "target_branch": "main",
                "title": mr_title,
                "description": mr_body,
                "remove_source_branch": true,
            });

            let client = reqwest::blocking::Client::builder()
                .https_only(true)
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .context("failed to create HTTP client")?;

            match client
                .post(format!("{api_url}/projects/{project_id}/merge_requests"))
                .header("JOB-TOKEN", &token)
                .json(&mr_json)
                .send()
            {
                Ok(resp) if resp.status().is_success() => {
                    eprintln!("MR created via API: {mr_title}");
                }
                Ok(resp) => {
                    eprintln!(
                        "warning: API MR creation failed (HTTP {})",
                        resp.status()
                    );
                    eprintln!("  branch {branch} was pushed -- create MR manually");
                }
                Err(e) => {
                    eprintln!("warning: API MR creation failed ({e})");
                    eprintln!("  branch {branch} was pushed -- create MR manually");
                }
            }
        } else {
            eprintln!("warning: glab mr create failed and no CI_JOB_TOKEN available");
            eprintln!("  branch {branch} was pushed -- create MR manually");
        }
    } else {
        eprintln!("MR created: {mr_title}");
    }

    eprintln!("\n{}", "=".repeat(60));
    eprintln!("Applied: {}", applied_names.len());
    for name in &applied_names {
        eprintln!("  {name}");
    }

    Ok(())
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
        .filter_map(|(platform, sha)| {
            sha.as_ref().map(|hash| (platform.as_str(), hash.as_str()))
        })
        .collect();

    if !new_hashes.is_empty() {
        // Create the [tool.checksums] table if it doesn't exist yet.
        if tool_table.get("checksums").is_none() {
            tool_table.insert(
                "checksums",
                toml_edit::Item::Table(toml_edit::Table::new()),
            );
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

/// Format the checksum verification status for MR display.
fn format_checksum_status(candidate: &super::UpdateCandidate) -> String {
    if candidate.verified.is_empty() {
        return "no checksums".to_string();
    }
    let verified = candidate
        .verified
        .values()
        .filter(|v| **v == Some(true))
        .count();
    let total = candidate.verified.len();
    if verified == total {
        format!("{verified}/{total} verified")
    } else {
        let failed = candidate
            .verified
            .values()
            .filter(|v| **v == Some(false))
            .count();
        if failed > 0 {
            format!("{verified}/{total} verified, {failed} MISMATCH")
        } else {
            format!("{verified}/{total} verified")
        }
    }
}

/// Run a git command in the current directory.
fn run_git(args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute git {}", args.first().unwrap_or(&"")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "git {} failed (exit {}): {}",
            args.first().unwrap_or(&""),
            output.status,
            stderr.trim()
        );
    }

    Ok(())
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
                Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string()),
            ),
            (
                "linux-x64".to_string(),
                Some("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string()),
            ),
        ]);

        let result = update_tool_toml(input, "0.7.0", &checksums).unwrap().unwrap();

        assert!(result.contains("version = \"0.7.0\""), "version should be updated");
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

        let result = update_tool_toml(input, "0.7.0", &checksums).unwrap().unwrap();

        assert!(result.contains("version = \"0.7.0\""), "version should be updated");
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

        let result = update_tool_toml(input, "1.1.0", &checksums).unwrap().unwrap();

        assert!(result.contains("version = \"1.1.0\""), "version should be updated");
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

        let result = update_tool_toml(input, "1.1.0", &checksums).unwrap().unwrap();

        assert!(result.contains("version = \"1.1.0\""), "version should be updated");
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

        let result = update_tool_toml(input, "2.90.0", &checksums).unwrap().unwrap();

        assert!(result.contains("name = \"gh\""), "name preserved");
        assert!(result.contains("description = \"GitHub CLI\""), "description preserved");
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
