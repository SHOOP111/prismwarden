use crate::model::{Category, Severity};
use anyhow::{Context, Result, bail, ensure};
use globset::{Glob, GlobMatcher, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
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
        let mut text = String::new();
        std::fs::File::open(path)
            .context("cannot open configuration")?
            .take(1_048_577)
            .read_to_string(&mut text)
            .context("configuration must be UTF-8")?;
        ensure!(text.len() <= 1_048_576, "configuration exceeds 1 MiB");
        // TOML diagnostics can echo the source, which might contain secrets.
        let config: Self = toml::from_str(&text).map_err(|_| {
            anyhow::anyhow!("invalid configuration TOML; see docs/CONFIGURATION.md")
        })?;
        ensure!(
            config.schema_version == 1,
            "unsupported configuration schema"
        );
        ensure!(
            config.rules.len() <= 64,
            "at most 64 custom rules are allowed"
        );
        Ok(config)
    }
}

pub struct Policy {
    pub excludes: GlobSet,
    allow: Vec<(String, GlobMatcher)>,
}

impl Policy {
    pub fn compile(config: &Config, known_rules: &BTreeSet<String>) -> Result<Self> {
        ensure!(
            config.schema_version == 1,
            "unsupported configuration schema"
        );
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
        let mut allow = Vec::new();
        for entry in &config.allow {
            if entry.reason.trim().is_empty() {
                bail!("every allowlist entry requires a nonempty reason");
            }
            let matcher = Glob::new(&entry.path)
                .map_err(|_| anyhow::anyhow!("invalid allowlist glob"))?
                .compile_matcher();
            allow.push((entry.rule.clone(), matcher));
        }
        Ok(Self {
            excludes: builder.build()?,
            allow,
        })
    }

    pub fn allows(&self, rule: &str, path: &str) -> bool {
        self.allow
            .iter()
            .any(|(id, glob)| id == rule && glob.is_match(path))
    }
}
