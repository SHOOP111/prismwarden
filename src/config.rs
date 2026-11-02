use crate::file_io;
use crate::model::{Category, Severity};
use anyhow::{Context, Result, bail, ensure};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRule {
    pub id: String,
    pub title: String,
    pub remediation: String,
    pub severity: Severity,
    pub category: Category,
    pub pattern: String,
    #[serde(default)]
    pub capture: usize,
    pub min_entropy: Option<f64>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub rule: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub exclude: Vec<String>,
    pub disable_rules: BTreeSet<String>,
    pub severity: BTreeMap<String, Severity>,
    pub allow: Vec<AllowEntry>,
    pub rules: Vec<CustomRule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            exclude: Vec::new(),
            disable_rules: BTreeSet::new(),
            severity: BTreeMap::new(),
            allow: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl Config {
    /// Configuration is explicit, never auto-loaded from an untrusted scan tree.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = file_io::read_input(path, 1_048_576).context("cannot load configuration")?;
        let text = std::str::from_utf8(&bytes).context("configuration must be UTF-8")?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        // TOML diagnostics can echo the source, which might contain secrets.
        let config: Self = toml::from_str(text).map_err(|_| {
            anyhow::anyhow!("invalid configuration TOML; see docs/CONFIGURATION.md")
        })?;
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported configuration schema");
        ensure!(self.rules.len() <= 64, "at most 64 custom rules are allowed");
        ensure!(
            self.exclude.len() <= 2048 && self.allow.len() <= 2048,
            "at most 2048 exclusion globs and 2048 allowlist entries are allowed"
        );
        for pattern in self.exclude.iter().chain(self.allow.iter().map(|entry| &entry.path))
            .chain(self.rules.iter().filter_map(|rule| rule.path.as_ref()))
        {
            ensure!(!pattern.is_empty() && pattern.len() <= 4096, "path globs must contain 1-4096 bytes");
        }
        for entry in &self.allow {
            ensure!(entry.reason.len() <= 1024, "allowlist reason exceeds 1024 bytes");
        }
        Ok(())
    }
}

pub struct Policy {
    pub excludes: GlobSet,
    allow: BTreeMap<String, GlobSet>,
}

impl Policy {
    pub fn compile(config: &Config, known_rules: &BTreeSet<String>) -> Result<Self> {
        config.validate()?;
        for id in config
            .disable_rules
            .iter()
            .chain(config.severity.keys())
            .chain(config.allow.iter().map(|a| &a.rule))
        {
            ensure!(
                known_rules.contains(id),
                "policy references an unknown rule ID"
            );
        }
        let mut builder = GlobSetBuilder::new();
        for pattern in &config.exclude {
            builder.add(Glob::new(pattern).map_err(|_| anyhow::anyhow!("invalid exclusion glob"))?);
        }
        let mut allow: BTreeMap<String, GlobSetBuilder> = BTreeMap::new();
        for entry in &config.allow {
            if entry.reason.trim().is_empty() {
                bail!("every allowlist entry requires a nonempty reason");
            }
            let glob = Glob::new(&entry.path)
                .map_err(|_| anyhow::anyhow!("invalid allowlist glob"))?;
            allow.entry(entry.rule.clone()).or_default().add(glob);
        }
        Ok(Self {
            excludes: builder.build().map_err(|_| anyhow::anyhow!("exclusion globs exceed limits"))?,
            allow: allow.into_iter().map(|(id, builder)| {
                builder.build().map(|set| (id, set))
                    .map_err(|_| anyhow::anyhow!("allowlist globs exceed limits"))
            }).collect::<Result<_>>()?,
        })
    }

    pub fn allows(&self, rule: &str, path: &str) -> bool {
        self.allow.get(rule).is_some_and(|globs| globs.is_match(path))
    }
}
