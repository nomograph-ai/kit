//! CI pipeline commands for the three-pipeline supply chain architecture.
//!
//! Pipeline 1 -- Sense: detect upstream changes (scheduled, read-only)
//! Pipeline 2 -- Respond: LLM evaluation + MR creation (triggered by sense)
//! Pipeline 3 -- Verify: independent validation on MR (triggered by MR)
//!
//! Legacy aliases: check -> sense, evaluate + apply -> respond.

pub mod apply;
pub mod check;
pub mod evaluate;
pub mod sense;
pub mod verify_registry;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An update candidate discovered by the check/sense phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCandidate {
    pub name: String,
    pub current_version: String,
    pub new_version: String,
    pub tag: String,
    /// SHA256 per platform (key: "macos-arm64" / "linux-x64").
    /// None value means download failed for that platform.
    pub checksums: HashMap<String, Option<String>>,
    /// Verification status per platform.
    /// true = verified against upstream, false = mismatch, None = no checksum file.
    pub verified: HashMap<String, Option<bool>>,
    /// Optional note (e.g. "npm package -- integrity verified by npm on install").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Output of the check phase (legacy format, still used by evaluate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckOutput {
    pub updates: Vec<UpdateCandidate>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub advisories: HashMap<String, Vec<Advisory>>,
    pub tools_checked: usize,
    pub updates_found: usize,
}

/// A security advisory from the GitHub Advisory Database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub severity: String,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Sense report types (Pipeline 1 output)
// ---------------------------------------------------------------------------

/// The version bump magnitude.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BumpLevel {
    Patch,
    Minor,
    Major,
}

impl std::fmt::Display for BumpLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Patch => f.write_str("patch"),
            Self::Minor => f.write_str("minor"),
            Self::Major => f.write_str("major"),
        }
    }
}

/// Risk level for a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Risk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

/// The type of finding detected during sense.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    VersionBump,
    AdvisoryFound,
}

/// A single classified finding from the sense phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenseFinding {
    pub tool: String,
    #[serde(rename = "type")]
    pub finding_type: FindingType,
    pub current: String,
    pub available: String,
    pub bump: BumpLevel,
    pub checksums_verified: bool,
    pub advisories: Vec<Advisory>,
    pub risk: Risk,
    /// Trust tier from tool definition.
    pub tier: String,
    /// Additional notes (e.g. checksum status details).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Raw checksums per platform for downstream use.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub checksums: HashMap<String, Option<String>>,
    /// Raw verification status per platform for downstream use.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub verified: HashMap<String, Option<bool>>,
    /// The release tag.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
}

/// Output of the sense phase (Pipeline 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenseReport {
    pub findings: Vec<SenseFinding>,
    pub tools_checked: usize,
    /// Infrastructure errors (things that should fail the pipeline).
    #[serde(default)]
    pub infrastructure_errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Evaluate / Respond types (Pipeline 2)
// ---------------------------------------------------------------------------

/// A single evaluated update with its disposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluatedUpdate {
    #[serde(flatten)]
    pub candidate: UpdateCandidate,
    /// "auto-approved", "approve", "flag", "reject"
    pub evaluation: String,
    #[serde(default)]
    pub review_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval_reason: Option<String>,
}

/// Output of the evaluate phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateOutput {
    pub evaluated: Vec<EvaluatedUpdate>,
    pub summary: EvaluateSummary,
}

/// Summary counts from evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateSummary {
    pub approved: usize,
    pub flagged: usize,
    pub rejected: usize,
}

// ---------------------------------------------------------------------------
// Verify-registry types (Pipeline 3)
// ---------------------------------------------------------------------------

/// Result of verifying a single tool in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolVerifyResult {
    pub name: String,
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether checksums re-verified successfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksums_verified: Option<bool>,
}

/// Output of the verify-registry command (Pipeline 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRegistryOutput {
    pub tools_checked: usize,
    pub valid: usize,
    pub invalid: usize,
    pub results: Vec<ToolVerifyResult>,
}

// ---------------------------------------------------------------------------
// Apply output types (kit apply → apply-result.json → CI shell)
// ---------------------------------------------------------------------------

/// A group of updates that share the same merge policy.
///
/// The CI pipeline creates one branch + MR per group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyGroup {
    /// Updates in this group.
    pub applied: Vec<AppliedUpdate>,
    /// Suggested git branch name.
    pub branch_hint: String,
    /// Pre-built commit message.
    pub commit_message: String,
    /// MR title.
    pub mr_title: String,
    /// MR description body (markdown).
    pub mr_body: String,
    /// Whether this group qualifies for auto-merge.
    pub auto_merge_eligible: bool,
}

/// Output of the apply phase — the contract between kit and CI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyOutput {
    /// Updates eligible for auto-merge per registry policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_merge_group: Option<ApplyGroup>,
    /// Updates that need human review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_group: Option<ApplyGroup>,
    /// Names of rejected updates (not applied).
    pub rejected_names: Vec<String>,
    /// Names of flagged updates (applied but need human review).
    pub flagged_names: Vec<String>,
}

/// A single update that was applied to a tool TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedUpdate {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
    /// Relative path to the modified file (e.g. "tools/gh.toml").
    pub file: String,
    /// Evaluation disposition: "auto-approved", "approve", or "flag".
    pub evaluation: String,
    /// Version bump level: "patch", "minor", or "major".
    pub bump: String,
    /// Tool trust tier from TOML definition.
    pub tier: String,
    /// Whether checksums were verified for all platforms.
    pub checksums_verified: bool,
    /// LLM or rule-based evaluation reason (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval_reason: Option<String>,
    /// Structured review reasons (e.g. "major bump", "checksum mismatch").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_reasons: Vec<String>,
}

// Re-export the entry points.
pub use apply::apply;
pub use check::check;
pub use evaluate::evaluate;
pub use sense::sense;
pub use verify_registry::verify_registry;
