//! Correlations are review hypotheses, not proven exploit paths or extra findings.
use crate::model::{Category, Correlation, Finding};
use std::collections::{BTreeMap, BTreeSet};

pub fn analyze(findings: &[Finding]) -> Vec<Correlation> {
    let mut output = Vec::new();
    let secrets: Vec<_> = findings
        .iter()
        .filter(|f| f.category == Category::Secret)
        .collect();
    let automation: Vec<_> = findings
        .iter()
        .filter(|f| ["CI001", "CI003", "CI005"].contains(&f.rule_id.as_str()))
        .collect();
    let mut members = Members::default();
    for (secret, workflow) in secrets.iter().zip(automation.iter().cycle()) {
        if !members.pair(secret, workflow) {
            break;
        }
    }
    members.finish(&mut output, "EXP001", "Credential exposure alongside risky automation",
        "This tree contains both credential-shaped material and privileged or input-sensitive automation. Review whether the workflow can access the material; co-occurrence alone does not prove reachability.");

    // One representative broad copy per build directory is enough to support a pair.
    let mut copies = BTreeMap::new();
    for finding in findings.iter().filter(|f| f.rule_id == "RUN001") {
        copies.entry(parent(&finding.path)).or_insert(finding);
    }
    let mut members = Members::default();
    'sensitive: for sensitive in findings.iter().filter(|f| {
        f.category == Category::Secret
            || ["ART001", "ART002", "ART004"].contains(&f.rule_id.as_str())
    }) {
        let mut directory = parent(&sensitive.path);
        loop {
            if let Some(copy) = copies.get(directory)
                && !members.pair(sensitive, copy)
            {
                break 'sensitive;
            }
            if directory.is_empty() {
                break;
            }
            directory = parent(directory);
        }
    }
    members.finish(&mut output, "EXP002", "Sensitive material near a broad container copy",
        "Sensitive material lies at or below a Dockerfile directory with a broad COPY/ADD. Verify the actual build context and .dockerignore; neither is resolved by this heuristic.");

    let mut bindings = BTreeMap::new();
    for finding in findings.iter().filter(|f| f.rule_id == "RUN003") {
        bindings.entry(&finding.path).or_insert(finding);
    }
    let mut members = Members::default();
    for debug in findings.iter().filter(|f| f.rule_id == "RUN005") {
        if let Some(binding) = bindings.get(&debug.path)
            && !members.pair(debug, binding)
        {
            break;
        }
    }
    members.finish(&mut output, "EXP003", "Debug configuration with an all-interface listener",
        "The same file enables debug mode and an all-interface listener. Confirm that these settings reach the same service and inspect authentication and network policy.");
    output
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// Retain whole supporting pairs, never a hash-sorted sample that loses one side.
#[derive(Default)]
struct Members(BTreeSet<String>);

impl Members {
    fn pair(&mut self, left: &Finding, right: &Finding) -> bool {
        let additional = usize::from(!self.0.contains(&left.fingerprint))
            + usize::from(
                left.fingerprint != right.fingerprint && !self.0.contains(&right.fingerprint),
            );
        if self.0.len() + additional > 16 {
            return false;
        }
        self.0.insert(left.fingerprint.clone());
        self.0.insert(right.fingerprint.clone());
        true
    }

    fn finish(self, output: &mut Vec<Correlation>, id: &str, title: &str, explanation: &str) {
        if !self.0.is_empty() {
            output.push(Correlation {
                id: id.into(),
                title: title.into(),
                explanation: explanation.into(),
                members: self.0.into_iter().collect(),
            });
        }
    }
}
