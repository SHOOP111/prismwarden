use crate::model::{Report, SCHEMA_VERSION};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

/// No source paths, values, or timestamps: suitable for reviewed version control.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub schema_version: u32,
    pub fingerprints: BTreeSet<String>,
}

impl Default for Baseline {
    fn default() -> Self { Self::empty() }
}

impl Baseline {
    pub fn empty() -> Self {
        Self { schema_version: SCHEMA_VERSION, fingerprints: BTreeSet::new() }
    }

    pub fn from_report(report: &Report) -> Result<Self> {
        ensure!(report.complete, "refusing to baseline an incomplete scan");
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            fingerprints: report.findings.iter().map(|f| f.fingerprint.clone()).collect(),
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .context("cannot open baseline")?
            .take(8_388_609)
            .read_to_end(&mut bytes)
            .context("cannot read baseline")?;
        ensure!(bytes.len() <= 8_388_608, "baseline exceeds 8 MiB");
        let baseline: Self = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid baseline JSON"))?;
        ensure!(baseline.schema_version == SCHEMA_VERSION, "unsupported baseline schema");
        ensure!(baseline.fingerprints.len() <= 100_000, "baseline has too many entries");
        ensure!(baseline.fingerprints.iter().all(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())), "invalid baseline fingerprint");
        Ok(baseline)
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }
}
