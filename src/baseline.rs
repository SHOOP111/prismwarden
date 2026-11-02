use crate::file_io;
use crate::model::{Report, SCHEMA_VERSION};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// No source paths, values, or timestamps: suitable for reviewed version control.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub schema_version: u32,
    pub fingerprints: BTreeSet<String>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self::empty()
    }
}

impl Baseline {
    pub fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            fingerprints: BTreeSet::new(),
        }
    }

    pub fn from_report(report: &Report) -> Result<Self> {
        ensure!(report.complete, "refusing to baseline an incomplete scan");
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            fingerprints: report
                .findings
                .iter()
                .map(|f| f.fingerprint.clone())
                .collect(),
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = file_io::read_input(path, 8_388_608).context("cannot load baseline")?;
        let baseline: Self =
            serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid baseline JSON"))?;
        baseline.validate()?;
        Ok(baseline)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported baseline schema"
        );
        ensure!(
            self.fingerprints.len() <= 100_000,
            "baseline has too many entries"
        );
        ensure!(
            self.fingerprints.iter().all(|s| s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
            "invalid baseline fingerprint"
        );
        Ok(())
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }
}
