//! CI pipeline commands: check, evaluate, apply.
//!
//! These implement the three-phase update pipeline that replaces
//! the Python scripts (check.py, evaluate.py, validate.py).

pub mod apply;
pub mod check;
pub mod evaluate;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An update candidate discovered by the check phase.
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

/// Output of the check phase.
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

// Re-export the entry points.
pub use apply::apply;
pub use check::check;
pub use evaluate::evaluate;
