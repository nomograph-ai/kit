//! Phase 2: Evaluate update candidates using rules and LLM judgment.
//!
//! Reads updates.json from Phase 1. For each update:
//! - Auto-approve if checksums verified on all platforms AND not a major bump
//! - Send to Haiku if checksum missing/failed, major version bump, or download failure
//! - Reject if checksum mismatch (verified = false)
//!
//! SECURITY: Never send release notes to the LLM (S-4). Only send tool name,
//! versions, and checksum status.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use super::{
    CheckOutput, EvaluateOutput, EvaluateSummary, EvaluatedUpdate, SenseReport, UpdateCandidate,
};

/// Run the evaluate phase.
///
/// Reads `input` (updates.json or sense-report.json), classifies each update,
/// optionally calls Haiku for edge cases, and writes `output` (evaluated.json).
///
/// Accepts both legacy CheckOutput format and new SenseReport format.
pub fn evaluate(input: &Path, output: &Path) -> Result<()> {
    let content = std::fs::read_to_string(input)
        .with_context(|| format!("failed to read {}", input.display()))?;

    // Try sense-report.json format first, fall back to legacy updates.json
    let (data, sense_context) =
        if let Ok(sense_report) = serde_json::from_str::<SenseReport>(&content) {
            let check_output = sense_report_to_check_output(&sense_report);
            (check_output, Some(sense_report.findings))
        } else {
            let check_output: CheckOutput = serde_json::from_str(&content)
                .context("failed to parse input as updates.json or sense-report.json")?;
            (check_output, None)
        };

    if data.updates.is_empty() {
        eprintln!("No updates to evaluate");
        let result = EvaluateOutput {
            evaluated: vec![],
            summary: EvaluateSummary {
                approved: 0,
                flagged: 0,
                rejected: 0,
            },
        };
        let json = serde_json::to_string_pretty(&result)?;
        std::fs::write(output, &json)?;
        return Ok(());
    }

    // Store sense context for richer MR descriptions
    let _ = sense_context;

    eprintln!("kit evaluate: evaluating {} updates\n", data.updates.len());

    let (needs_review, auto_approved) = classify(&data.updates);

    eprintln!("  Auto-approved: {}", auto_approved.len());
    eprintln!("  Needs review:  {}", needs_review.len());

    let mut evaluated: Vec<EvaluatedUpdate> = auto_approved;

    if !needs_review.is_empty() {
        let api_key = std::env::var("ANTHROPIC_API_KEY").ok();

        if let Some(key) = api_key {
            let model = std::env::var("CLAUDE_MODEL")
                .unwrap_or_else(|_| "claude-haiku-4-5-20251001".to_string());
            eprintln!("\n  Calling {model} for {} updates...", needs_review.len());

            let prompt = build_prompt(&needs_review);
            match call_haiku(&key, &model, &prompt) {
                Ok(Some(decisions)) => {
                    let decision_map: HashMap<String, HaikuDecision> =
                        decisions.into_iter().map(|d| (d.name.clone(), d)).collect();

                    for mut update in needs_review {
                        let decision = decision_map.get(&update.candidate.name);
                        update.evaluation = decision
                            .map(|d| d.action.clone())
                            .unwrap_or_else(|| "flag".to_string());
                        update.eval_reason = Some(
                            decision
                                .map(|d| d.reason.clone())
                                .unwrap_or_else(|| "no response from LLM".to_string()),
                        );
                        evaluated.push(update);
                    }
                }
                Ok(None) => {
                    eprintln!("  warning: Haiku returned empty response, flagging all");
                    for mut update in needs_review {
                        update.evaluation = "flag".to_string();
                        update.eval_reason = Some("LLM response empty".to_string());
                        evaluated.push(update);
                    }
                }
                Err(e) => {
                    eprintln!("  warning: Haiku call failed ({e:#}), flagging all");
                    for mut update in needs_review {
                        update.evaluation = "flag".to_string();
                        update.eval_reason = Some(format!("LLM unavailable: {e}"));
                        evaluated.push(update);
                    }
                }
            }
        } else {
            eprintln!("  warning: ANTHROPIC_API_KEY not set, flagging all");
            for mut update in needs_review {
                update.evaluation = "flag".to_string();
                update.eval_reason = Some("No ANTHROPIC_API_KEY set".to_string());
                evaluated.push(update);
            }
        }
    }

    // Count outcomes
    let approved = evaluated
        .iter()
        .filter(|e| e.evaluation == "auto-approved" || e.evaluation == "approve")
        .count();
    let flagged = evaluated.iter().filter(|e| e.evaluation == "flag").count();
    let rejected = evaluated
        .iter()
        .filter(|e| e.evaluation == "reject")
        .count();

    let result = EvaluateOutput {
        evaluated,
        summary: EvaluateSummary {
            approved,
            flagged,
            rejected,
        },
    };

    let json =
        serde_json::to_string_pretty(&result).context("failed to serialize evaluated.json")?;
    std::fs::write(output, &json)
        .with_context(|| format!("failed to write {}", output.display()))?;

    eprintln!("\n{}", "=".repeat(60));
    eprintln!("Approved: {approved}");
    eprintln!("Flagged:  {flagged}");
    eprintln!("Rejected: {rejected}");

    if rejected > 0 {
        eprintln!("\nWARNING: {rejected} updates rejected -- these will NOT be applied");
        eprintln!("  Rejected updates are included in the MR description for audit.");
        eprintln!("  Approved updates will still be applied.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Classify updates into auto-approved and needs-review.
fn classify(updates: &[UpdateCandidate]) -> (Vec<EvaluatedUpdate>, Vec<EvaluatedUpdate>) {
    let mut needs_review = Vec::new();
    let mut auto_approved = Vec::new();

    for update in updates {
        let mut reasons: Vec<String> = Vec::new();

        // Checksum mismatch: reject immediately
        let has_mismatch = update.verified.values().any(|v| *v == Some(false));
        if has_mismatch {
            reasons.push("CHECKSUM MISMATCH -- possible supply chain attack".to_string());
        }

        // Checksum could not be verified
        if update.verified.values().any(|v| v.is_none()) {
            reasons.push("checksum could not be verified against upstream".to_string());
        }

        // Download failed for one or more platforms
        if update.checksums.values().any(|v| v.is_none()) {
            reasons.push("download failed for one or more platforms".to_string());
        }

        // Major version bump
        if is_major_bump(&update.current_version, &update.new_version) {
            reasons.push(format!(
                "major version bump: {} -> {}",
                update.current_version, update.new_version
            ));
        }

        if reasons.is_empty() {
            auto_approved.push(EvaluatedUpdate {
                candidate: update.clone(),
                evaluation: "auto-approved".to_string(),
                review_reasons: vec![],
                eval_reason: None,
            });
        } else {
            // Reject outright on checksum mismatch
            let eval = if has_mismatch {
                "reject".to_string()
            } else {
                String::new() // will be filled by LLM or fallback
            };

            needs_review.push(EvaluatedUpdate {
                candidate: update.clone(),
                evaluation: eval,
                review_reasons: reasons,
                eval_reason: if has_mismatch {
                    Some("checksum mismatch".to_string())
                } else {
                    None
                },
            });
        }
    }

    // Separate out already-rejected items so they don't go to Haiku
    let (rejected, actual_review): (Vec<_>, Vec<_>) = needs_review
        .into_iter()
        .partition(|u| u.evaluation == "reject");

    // Rejected items go straight to the auto list
    let mut final_auto = auto_approved;
    final_auto.extend(rejected);

    (actual_review, final_auto)
}

/// Check if this is a major version bump (first numeric segment changed).
fn is_major_bump(current: &str, new: &str) -> bool {
    let cur_major = current.split('.').next().unwrap_or("0");
    let new_major = new.split('.').next().unwrap_or("0");
    cur_major != new_major
}

// ---------------------------------------------------------------------------
// Haiku LLM integration
// ---------------------------------------------------------------------------

/// Sanitize a field for LLM prompt inclusion.
/// Strips non-printable-ASCII and truncates.
fn sanitize(value: &str, max_len: usize) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| ('\x20'..='\x7E').contains(c))
        .take(max_len)
        .collect();
    cleaned
}

/// Build the LLM prompt from updates needing review.
fn build_prompt(updates: &[EvaluatedUpdate]) -> String {
    let mut tools_summary = Vec::new();

    for update in updates {
        let name = sanitize(&update.candidate.name, 64);
        let cur = sanitize(&update.candidate.current_version, 32);
        let new = sanitize(&update.candidate.new_version, 32);
        let reasons: Vec<String> = update
            .review_reasons
            .iter()
            .map(|r| sanitize(r, 128))
            .collect();
        let reasons_str = reasons.join("; ");

        // S-4: only send tool name, versions, checksum status -- never release notes
        let checksums_json = serde_json::to_string(&update.candidate.checksums).unwrap_or_default();
        let verified_json = serde_json::to_string(&update.candidate.verified).unwrap_or_default();

        tools_summary.push(format!(
            "- {name}: {cur} -> {new}\n\
             \x20 Reasons for review: {reasons_str}\n\
             \x20 Checksums: {checksums_json}\n\
             \x20 Verified: {verified_json}"
        ));
    }

    format!(
        "You are a supply chain security reviewer for a tool registry.\n\
         \n\
         The following tool updates need judgment. For each one, respond with a JSON\n\
         array where each element has:\n\
         - \"name\": tool name\n\
         - \"action\": one of \"approve\", \"flag\", \"reject\"\n\
         - \"reason\": brief explanation\n\
         \n\
         Rules:\n\
         - REJECT any update with a checksum mismatch (possible supply chain attack)\n\
         - FLAG major version bumps for human review (don't reject, just flag)\n\
         - FLAG download failures (might be transient, might be naming change)\n\
         - APPROVE everything else that has verified checksums\n\
         \n\
         Updates requiring review:\n\
         {}\n\
         \n\
         Respond with ONLY the JSON array, no other text.",
        tools_summary.join("\n")
    )
}

/// A decision from the Haiku LLM.
#[derive(Debug, serde::Deserialize)]
struct HaikuDecision {
    name: String,
    action: String,
    reason: String,
}

/// Call Claude Haiku via the Anthropic API.
fn call_haiku(api_key: &str, model: &str, prompt: &str) -> Result<Option<Vec<HaikuDecision>>> {
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(90))
        .build()
        .context("failed to build HTTP client")?;

    let payload = serde_json::json!({
        "model": model,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    });

    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&payload)
        .send()
        .context("failed to call Anthropic API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        anyhow::bail!("Anthropic API returned HTTP {status}: {body}");
    }

    let body: serde_json::Value = resp.json().context("failed to parse API response")?;

    let text = body["content"]
        .as_array()
        .and_then(|arr: &Vec<serde_json::Value>| arr.first())
        .and_then(|block| {
            if block["type"].as_str() == Some("text") {
                block["text"].as_str()
            } else {
                None
            }
        });

    let text = match text {
        Some(t) => t,
        None => return Ok(None),
    };

    // Strip markdown code fences that Haiku sometimes wraps around JSON
    let cleaned = strip_code_fences(text);

    let decisions: Vec<HaikuDecision> =
        serde_json::from_str(&cleaned).context("failed to parse Haiku JSON response")?;

    Ok(Some(decisions))
}

/// Convert a SenseReport into the legacy CheckOutput format for classification.
fn sense_report_to_check_output(report: &SenseReport) -> CheckOutput {
    let updates: Vec<UpdateCandidate> = report
        .findings
        .iter()
        .filter(|f| f.current != f.available) // Only actual version bumps
        .map(|f| UpdateCandidate {
            name: f.tool.clone(),
            current_version: f.current.clone(),
            new_version: f.available.clone(),
            tag: f.tag.clone(),
            checksums: f.checksums.clone(),
            verified: f.verified.clone(),
            note: f.note.clone(),
        })
        .collect();

    let advisories: HashMap<String, Vec<super::Advisory>> = report
        .findings
        .iter()
        .filter(|f| !f.advisories.is_empty())
        .map(|f| (f.tool.clone(), f.advisories.clone()))
        .collect();

    CheckOutput {
        updates_found: updates.len(),
        updates,
        errors: report.infrastructure_errors.clone(),
        advisories,
        tools_checked: report.tools_checked,
    }
}

/// Strip markdown code fences (```json ... ```) from a string.
fn strip_code_fences(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.starts_with("```") {
        let mut lines: Vec<&str> = trimmed.lines().collect();
        // Remove opening fence
        if !lines.is_empty() {
            lines.remove(0);
        }
        // Remove closing fence
        if lines.last().is_some_and(|l| l.trim() == "```") {
            lines.pop();
        }
        lines.join("\n")
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_major_bump() {
        assert!(is_major_bump("1.2.3", "2.0.0"));
        assert!(!is_major_bump("1.2.3", "1.3.0"));
        assert!(!is_major_bump("1.2.3", "1.2.4"));
        assert!(is_major_bump("0.9.0", "1.0.0"));
    }

    #[test]
    fn test_strip_code_fences() {
        let input = "```json\n[{\"name\": \"test\"}]\n```";
        assert_eq!(strip_code_fences(input), "[{\"name\": \"test\"}]");

        let input = "[{\"name\": \"test\"}]";
        assert_eq!(strip_code_fences(input), "[{\"name\": \"test\"}]");

        let input = "```\n[{\"name\": \"test\"}]\n```";
        assert_eq!(strip_code_fences(input), "[{\"name\": \"test\"}]");
    }

    #[test]
    fn test_sanitize() {
        assert_eq!(sanitize("hello world", 128), "hello world");
        assert_eq!(sanitize("hello\x00world", 128), "helloworld");
        assert_eq!(sanitize("abcdef", 3), "abc");
    }

    #[test]
    fn test_classify_auto_approve() {
        let update = UpdateCandidate {
            name: "test".to_string(),
            current_version: "1.0.0".to_string(),
            new_version: "1.0.1".to_string(),
            tag: "v1.0.1".to_string(),
            checksums: HashMap::from([
                ("macos-arm64".to_string(), Some("abc".to_string())),
                ("linux-x64".to_string(), Some("def".to_string())),
            ]),
            verified: HashMap::from([
                ("macos-arm64".to_string(), Some(true)),
                ("linux-x64".to_string(), Some(true)),
            ]),
            note: None,
        };

        let (review, auto) = classify(&[update]);
        assert!(review.is_empty());
        assert_eq!(auto.len(), 1);
        assert_eq!(auto[0].evaluation, "auto-approved");
    }

    #[test]
    fn test_classify_reject_mismatch() {
        let update = UpdateCandidate {
            name: "bad".to_string(),
            current_version: "1.0.0".to_string(),
            new_version: "1.0.1".to_string(),
            tag: "v1.0.1".to_string(),
            checksums: HashMap::from([("macos-arm64".to_string(), Some("abc".to_string()))]),
            verified: HashMap::from([("macos-arm64".to_string(), Some(false))]),
            note: None,
        };

        let (review, auto) = classify(&[update]);
        assert!(review.is_empty());
        // Rejected items go to auto list (already decided)
        let rejected: Vec<_> = auto.iter().filter(|e| e.evaluation == "reject").collect();
        assert_eq!(rejected.len(), 1);
    }

    #[test]
    fn test_classify_major_bump_needs_review() {
        let update = UpdateCandidate {
            name: "big".to_string(),
            current_version: "1.2.3".to_string(),
            new_version: "2.0.0".to_string(),
            tag: "v2.0.0".to_string(),
            checksums: HashMap::from([("macos-arm64".to_string(), Some("abc".to_string()))]),
            verified: HashMap::from([("macos-arm64".to_string(), Some(true))]),
            note: None,
        };

        let (review, auto) = classify(&[update]);
        assert_eq!(review.len(), 1);
        assert!(auto.is_empty());
        assert!(review[0].review_reasons[0].contains("major version bump"));
    }
}
