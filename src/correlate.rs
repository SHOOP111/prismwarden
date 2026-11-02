//! Correlations are review hypotheses, not proven exploit paths or extra findings.
use crate::model::{Category, Correlation, Finding};
use std::collections::{BTreeMap, BTreeSet};

pub fn analyze(findings: &[Finding]) -> Vec<Correlation> {
    let mut output = Vec::new();
    let secrets: Vec<_> = findings.iter().filter(|f| f.category == Category::Secret).collect();
    let automation: Vec<_> = findings.iter().filter(|f| ["CI001", "CI003", "CI005"].contains(&f.rule_id.as_str())).collect();
    if !secrets.is_empty() && !automation.is_empty() {
        output.push(correlation("EXP001", "Credential exposure alongside risky automation",
            "This tree contains both credential-shaped material and privileged or input-sensitive automation. Review whether the workflow can access the material; co-occurrence alone does not prove reachability.",
            secrets.iter().chain(&automation).copied()));
    }
    let mut copies: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in findings.iter().filter(|f| f.rule_id == "RUN001") {
        let directory = finding.path.rsplit_once('/').map_or("", |(parent, _)| parent);
        copies.entry(directory).or_default().push(finding);
    }
    let mut build_members = BTreeSet::new();
    let mut matched_directories = BTreeSet::new();
    for sensitive in findings.iter().filter(|f| f.category == Category::Secret || ["ART001", "ART002", "ART004"].contains(&f.rule_id.as_str())) {
        let mut directory = sensitive.path.rsplit_once('/').map_or("", |(parent, _)| parent);
        loop {
            if copies.contains_key(directory) {
                build_members.insert(sensitive.fingerprint.clone());
                matched_directories.insert(directory);
            }
            if directory.is_empty() { break; }
            directory = directory.rsplit_once('/').map_or("", |(parent, _)| parent);
        }
    }
    for directory in matched_directories {
        build_members.extend(copies[directory].iter().map(|f| f.fingerprint.clone()));
    }
    if !build_members.is_empty() {
        output.push(Correlation {
            id: "EXP002".into(), title: "Sensitive material near a broad container copy".into(),
            explanation: "Sensitive material lies at or below a Dockerfile directory with a broad COPY/ADD. Verify the actual build context and .dockerignore; neither is resolved by this heuristic.".into(),
            members: build_members.into_iter().take(16).collect(),
        });
    }
    #[derive(Default)]
    struct Service<'a> { bindings: Vec<&'a Finding>, debug: Vec<&'a Finding> }
    let mut services: BTreeMap<&str, Service<'_>> = BTreeMap::new();
    for finding in findings {
        match finding.rule_id.as_str() {
            "RUN003" => services.entry(&finding.path).or_default().bindings.push(finding),
            "RUN005" => services.entry(&finding.path).or_default().debug.push(finding),
            _ => (),
        }
    }
    let mut service_members = Vec::new();
    for Service { bindings, debug } in services.values() {
        if !bindings.is_empty() && !debug.is_empty() { service_members.extend(bindings.iter().chain(debug).copied()); }
    }
    if !service_members.is_empty() {
        output.push(correlation("EXP003", "Debug configuration with an all-interface listener",
            "The same file enables debug mode and an all-interface listener. Confirm that these settings reach the same service and inspect authentication and network policy.", service_members));
    }
    output
}

fn correlation<'a>(id: &str, title: &str, explanation: &str, findings: impl IntoIterator<Item = &'a Finding>) -> Correlation {
    let fingerprints: BTreeSet<_> = findings.into_iter().map(|f| f.fingerprint.clone()).collect();
    Correlation { id: id.into(), title: title.into(), explanation: explanation.into(), members: fingerprints.into_iter().take(16).collect() }
}
