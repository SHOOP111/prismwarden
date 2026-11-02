use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Low => "low",
                Self::Medium => "medium",
                Self::High => "high",
                Self::Critical => "critical",
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Secret,
    Automation,
    Runtime,
    Privacy,
    Artifact,
}

/// Deliberately contains no matched text, snippets, or absolute root path.
/// Ordering is location-first, independent of worker scheduling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub rule_id: String,
    pub fingerprint: String,
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Notice {
    pub path: String,
    pub code: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statistics {
    pub entries_visited: u64,
    pub files_scheduled: u64,
    pub files_scanned: u64,
    pub bytes_read: u64,
    pub binary_files: u64,
    pub excluded_by_policy: u64,
    pub symlinks_skipped: u64,
    pub special_files_skipped: u64,
    pub baseline_suppressed: u64,
    pub allowlist_suppressed: u64,
    pub findings_omitted: u64,
    pub coverage_notices: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Correlation {
    pub id: String,
    pub title: String,
    pub explanation: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: String,
    pub version: String,
    pub rulepack_digest: String,
    pub complete: bool,
    pub statistics: Statistics,
    pub severity_counts: BTreeMap<String, u64>,
    pub findings: Vec<Finding>,
    pub correlations: Vec<Correlation>,
    pub notices: Vec<Notice>,
}

impl Report {
    /// 0 = policy passed, 1 = threshold exceeded, 3 = incomplete coverage.
    /// Operational/usage errors are handled by the CLI with exit code 2.
    pub fn exit_code(&self, threshold: Option<Severity>, allow_incomplete: bool) -> u8 {
        if !self.complete && !allow_incomplete {
            3
        } else if threshold.is_some_and(|s| self.findings.iter().any(|f| f.severity >= s)) {
            1
        } else {
            0
        }
    }
}

/// Domain-separated, length-delimited, relocation/line-shift-stable identity.
/// This is a digest, NOT encryption: low-entropy inputs can be guessed.
pub fn fingerprint(rule: &str, path: &str, evidence: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("prismwarden.finding.v1");
    for part in [rule.as_bytes(), path.as_bytes(), evidence] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().to_hex().to_string()
}
