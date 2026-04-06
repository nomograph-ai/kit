//! Phase 3: Apply evaluated updates to registry TOML files.
//!
//! Reads evaluated.json from Phase 2. For approved updates:
//! 1. Load the tool's TOML file from tools/<name>.toml
//! 2. Update version and inline checksums using toml_edit (preserve formatting)
//! 3. Write the file back
//! 4. Git add, commit, push to a new branch
//! 5. Create MR via glab CLI

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

        let mut doc = raw
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("failed to parse {} as TOML", tool_path.display()))?;

        // Update version
        if let Some(tool_table) = doc.get_mut("tool").and_then(|t| t.as_table_mut()) {
            tool_table["version"] = toml_edit::value(new_version.as_str());

            // Update inline checksums if present and we have new ones
            let checksums = &update.candidate.checksums;
            if !checksums.is_empty()
                && let Some(checksums_table) =
                    tool_table.get_mut("checksums").and_then(|t| t.as_table_mut())
            {
                for (platform, sha) in checksums {
                    if let Some(hash) = sha {
                        checksums_table[platform.as_str()] =
                            toml_edit::value(hash.as_str());
                    }
                }
            }
        } else {
            eprintln!("  warning: no [tool] table in {name}.toml, skipping");
            continue;
        }

        std::fs::write(&tool_path, doc.to_string())
            .with_context(|| format!("failed to write {}", tool_path.display()))?;

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

    // Build MR description
    let mut mr_body = String::from("## Tool Updates\n\n");

    if !to_apply.is_empty() {
        mr_body.push_str("### Approved\n\n");
        for update in &to_apply {
            if applied_names.contains(&update.candidate.name) {
                mr_body.push_str(&format!(
                    "- **{}**: {} -> {}\n",
                    update.candidate.name,
                    update.candidate.current_version,
                    update.candidate.new_version
                ));
            }
        }
        mr_body.push('\n');
    }

    if !flagged.is_empty() {
        mr_body.push_str("### Flagged for Review\n\n");
        for f in &flagged {
            mr_body.push_str(&format!(
                "- **{}**: {} -> {} -- {}\n",
                f.candidate.name,
                f.candidate.current_version,
                f.candidate.new_version,
                f.eval_reason.as_deref().unwrap_or("needs review")
            ));
        }
        mr_body.push('\n');
    }

    if !rejected.is_empty() {
        mr_body.push_str("### Rejected\n\n");
        for r in &rejected {
            mr_body.push_str(&format!(
                "- **{}**: {} -> {} -- {}\n",
                r.candidate.name,
                r.candidate.current_version,
                r.candidate.new_version,
                r.eval_reason.as_deref().unwrap_or("rejected")
            ));
        }
        mr_body.push('\n');
    }

    mr_body.push_str("\n---\n*Generated by kit CI*\n");

    // Create MR via glab
    let mr_title = format!("kit: tool updates {today}");
    let status = Command::new("glab")
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
        .context("failed to run glab mr create")?;

    if !status.success() {
        eprintln!("warning: glab mr create failed (exit {})", status);
        eprintln!("  branch {branch} was pushed -- create MR manually");
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
