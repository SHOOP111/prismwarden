use crate::config::{Config, CustomRule};
use crate::model::{Category, Finding, Severity, fingerprint};
use anyhow::{Result, ensure};
use globset::{Glob, GlobMatcher};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: Category,
    pub remediation: String,
}

#[derive(Clone, Copy)]
enum Scope { Any, Workflow, Docker, Config }

enum Detector {
    Content { regex: Regex, capture: usize, entropy: Option<f64>, unpinned: bool },
    Env,
    State,
    DesktopMetadata,
    KeyStore,
    Permissions,
}

struct Rule {
    info: RuleInfo,
    detector: Detector,
    scope: Scope,
    path: Option<GlobMatcher>,
}

pub struct RulePack {
    rules: Vec<Rule>,
    prefilter: RegexSet,
    indices: Vec<usize>,
    known: BTreeSet<String>,
    pub digest: String,
}

impl RulePack {
    pub fn compile(config: &Config) -> Result<Self> {
        ensure!(config.rules.len() <= 64, "at most 64 custom rules are allowed");
        let mut rules = builtins()?;
        let mut known: BTreeSet<_> = rules.iter().map(|r| r.info.id.clone()).collect();
        for custom in &config.rules {
            ensure!(known.insert(custom.id.clone()), "duplicate rule ID");
            rules.push(compile_custom(custom)?);
        }
        for rule in &mut rules {
            if let Some(severity) = config.severity.get(&rule.info.id) {
                rule.info.severity = *severity;
            }
        }
        let mut digest = blake3::Hasher::new_derive_key("prismwarden.rulepack.v1");
        digest.update(env!("CARGO_PKG_VERSION").as_bytes());
        digest.update(&serde_json::to_vec(config)?);
        for rule in &rules {
            digest.update(&serde_json::to_vec(&rule.info)?);
            if let Detector::Content { regex, .. } = &rule.detector {
                digest.update(regex.as_str().as_bytes());
            }
        }
        rules.retain(|r| !config.disable_rules.contains(&r.info.id));
        rules.sort_by(|a, b| a.info.id.cmp(&b.info.id));
        let indices: Vec<_> = rules.iter().enumerate().filter_map(|(i, r)| matches!(r.detector, Detector::Content { .. }).then_some(i)).collect();
        let patterns: Vec<_> = indices.iter().map(|i| match &rules[*i].detector {
            Detector::Content { regex, .. } => regex.as_str(),
            _ => unreachable!(),
        }).collect();
        let prefilter = RegexSetBuilder::new(patterns).size_limit(32 * 1024 * 1024).build()
            .map_err(|_| anyhow::anyhow!("combined rule patterns exceed regex limits"))?;
        Ok(Self { rules, prefilter, indices, known, digest: digest.finalize().to_hex().to_string() })
    }

    pub fn catalog(&self) -> Vec<RuleInfo> {
        self.rules.iter().map(|r| r.info.clone()).collect()
    }

    pub fn known_ids(&self) -> &BTreeSet<String> { &self.known }

    /// Returns false if the caller's per-file candidate budget was exhausted.
    pub fn inspect_content(&self, path: &str, text: &str, mut emit: impl FnMut(Finding) -> bool) -> bool {
        let starts: Vec<usize> = std::iter::once(0).chain(text.match_indices('\n').map(|(i, _)| i + 1)).collect();
        for index in self.prefilter.matches(text) {
            let rule = &self.rules[self.indices[index]];
            if !rule.applies(path) { continue; }
            let Detector::Content { regex, capture, entropy, unpinned } = &rule.detector else { continue; };
            for captures in regex.captures_iter(text) {
                let Some(matched) = captures.get(*capture) else { continue; };
                let value = matched.as_str();
                if *unpinned && is_pinned_action(value) { continue; }
                if rule.info.category == Category::Secret && is_placeholder(value) { continue; }
                if entropy.is_some_and(|minimum| shannon_entropy(value.as_bytes()) < minimum) { continue; }
                let line_index = starts.partition_point(|s| *s <= matched.start()) - 1;
                let column = text[starts[line_index]..matched.start()].chars().count() + 1;
                let finding = rule.finding(path, line_index + 1, column, value.as_bytes());
                if !emit(finding) { return false; }
            }
        }
        true
    }

    pub fn inspect_path(&self, path: &str, unix_mode: Option<u32>, mut emit: impl FnMut(Finding) -> bool) -> bool {
        let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
        let sensitive_env = (name == ".env" || name.starts_with(".env."))
            && !["example", "sample", "template", "dist"].iter().any(|suffix| name.ends_with(suffix));
        let key_store = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"].contains(&name.as_str())
            || [".p12", ".pfx", ".kdbx"].iter().any(|suffix| name.ends_with(suffix));
        for rule in &self.rules {
            let hit = match rule.detector {
                Detector::Env => sensitive_env,
                Detector::State => name.ends_with(".tfstate") || name.ends_with(".tfstate.backup"),
                Detector::DesktopMetadata => [".ds_store", "thumbs.db", "desktop.ini"].contains(&name.as_str()),
                Detector::KeyStore => key_store,
                Detector::Permissions => (sensitive_env || key_store) && unix_mode.is_some_and(|mode| mode & 0o077 != 0),
                Detector::Content { .. } => false,
            };
            if hit && !emit(rule.finding(path, 1, 1, rule.info.id.as_bytes())) { return false; }
        }
        true
    }
}

impl Rule {
    fn applies(&self, path: &str) -> bool {
        if self.path.as_ref().is_some_and(|g| !g.is_match(path)) { return false; }
        match self.scope {
            Scope::Any => true,
            Scope::Workflow => path.starts_with(".github/workflows/") && (path.ends_with(".yml") || path.ends_with(".yaml")),
            Scope::Docker => path.rsplit('/').next().is_some_and(|n| n.eq_ignore_ascii_case("dockerfile") || n.to_ascii_lowercase().starts_with("dockerfile.")),
            Scope::Config => [".yml", ".yaml", ".toml", ".ini", ".conf", ".env", ".json", ".properties"].iter().any(|s| path.ends_with(s)) || path.rsplit('/').next().is_some_and(|n| n.starts_with(".env")),
        }
    }

    fn finding(&self, path: &str, line: usize, column: usize, evidence: &[u8]) -> Finding {
        Finding {
            path: path.to_owned(), line, column,
            rule_id: self.info.id.clone(),
            fingerprint: fingerprint(&self.info.id, path, evidence),
            severity: self.info.severity,
            category: self.info.category,
            title: self.info.title.clone(),
            remediation: self.info.remediation.clone(),
        }
    }
}

fn pattern_rule(id: &str, title: &str, severity: Severity, category: Category, remediation: &str, pattern: &str, scope: Scope) -> Result<Rule> {
    let regex = RegexBuilder::new(pattern).size_limit(2 * 1024 * 1024).build()
        .map_err(|_| anyhow::anyhow!("invalid or oversized rule regex"))?;
    Ok(Rule {
        info: RuleInfo { id: id.into(), title: title.into(), severity, category, remediation: remediation.into() },
        detector: Detector::Content { regex, capture: 0, entropy: None, unpinned: false },
        scope, path: None,
    })
}

fn compile_custom(custom: &CustomRule) -> Result<Rule> {
    ensure!(custom.id.len() >= 3 && custom.id.len() <= 32 && custom.id.starts_with(|c: char| c.is_ascii_uppercase()) && custom.id.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_' || c == b'-'), "custom rule IDs must be 3-32 uppercase ASCII identifier characters");
    ensure!(custom.pattern.len() <= 4096, "custom regex exceeds 4096 bytes");
    ensure!(!custom.title.trim().is_empty() && custom.title.len() <= 160 && !custom.remediation.trim().is_empty() && custom.remediation.len() <= 1024, "custom rules require a title (<=160 bytes) and remediation (<=1024 bytes)");
    ensure!(custom.min_entropy.is_none_or(|e| e.is_finite() && (0.0..=8.0).contains(&e)), "entropy threshold must be between 0 and 8");
    let mut rule = pattern_rule(&custom.id, &custom.title, custom.severity, custom.category, &custom.remediation, &custom.pattern, Scope::Any)?;
    if let Detector::Content { regex, capture, entropy, .. } = &mut rule.detector {
        ensure!(!regex.is_match(""), "custom regex must not match an empty string");
        ensure!(custom.capture < regex.captures_len(), "custom rule capture index does not exist");
        *capture = custom.capture;
        *entropy = custom.min_entropy;
    }
    rule.path = custom.path.as_ref().map(|p| Glob::new(p).map(|g| g.compile_matcher()).map_err(|_| anyhow::anyhow!("invalid custom rule path glob"))).transpose()?;
    Ok(rule)
}

fn builtins() -> Result<Vec<Rule>> {
    use Category::*;
    use Scope::*;
    use Severity::*;
    let rotate = "Revoke and rotate the credential; remove it from the tree and review history and access logs. Use a secret manager.";
    let mut rules = Vec::new();
    let definitions = [
        ("SEC001", "Private key material", Critical, Secret, rotate, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", Any),
        ("SEC002", "GitHub token-shaped credential", High, Secret, rotate, r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b", Any),
        ("SEC003", "AWS access key identifier", High, Secret, "Locate the paired secret, review IAM access, and rotate the key. An identifier alone does not prove usable access.", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", Any),
        ("SEC004", "Slack token-shaped credential", High, Secret, rotate, r"\bxox[baprs]-[A-Za-z0-9-]{20,200}\b", Any),
        ("SEC005", "Live Stripe secret-shaped key", High, Secret, rotate, r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,200}\b", Any),
        ("SEC006", "Google API key-shaped value", High, Secret, "Restrict the API key by application and API, review usage, and rotate if exposed.", r"\bAIza[A-Za-z0-9_-]{35}\b", Any),
        ("SEC007", "JWT-shaped token", Medium, Secret, "Determine whether the token grants access or exposes claims. Revoke its session if sensitive; never paste it into an online decoder.", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", Any),
        ("SEC008", "Credentials embedded in a URL", High, Secret, rotate, r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|https?)://[^\s:/@"']{1,64}:([^\s@/"']{3,128})@"#, Any),
        ("SEC009", "High-entropy assigned secret", High, Secret, rotate, r#"(?im)^[ \t]*(?:export[ \t]+)?["']?(?:[A-Za-z0-9_]*(?:password|passwd|api_key|api_secret|access_token|auth_token|client_secret|secret_key))["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9/+_=.!@#$%^&*\-]{16,160})"#, Any),
        ("SEC010", "PyPI upload token-shaped value", High, Secret, rotate, r"\bpypi-[A-Za-z0-9_-]{50,300}\b", Any),
        ("SEC011", "npm token-shaped credential", High, Secret, rotate, r"\bnpm_[A-Za-z0-9]{36}\b", Any),
        ("SEC012", "Hard-coded bearer authorization", High, Secret, rotate, r#"(?i)\bauthorization[ \t]*[:=][ \t]*["']?Bearer[ \t]+([A-Za-z0-9._~+/-]{20,300}=*)"#, Any),
        ("CI001", "Workflow grants write-all permissions", High, Automation, "Set top-level permissions to contents: read and grant minimal permissions only to the jobs that need them.", r"(?m)^[ \t]*permissions:[ \t]*write-all[ \t]*(?:#.*)?$", Workflow),
        ("CI002", "Action reference is not immutably pinned", Medium, Automation, "Pin external actions to a reviewed full 40-character commit SHA; pin Docker actions by sha256 digest.", r"(?m)^[ \t]*-?[ \t]*uses:[ \t]*([^\s#]+)", Workflow),
        ("CI003", "Privileged pull request trigger", High, Automation, "Review pull_request_target carefully. Never run untrusted pull-request code or interpolate untrusted input in a privileged job.", r"\bpull_request_target\b", Workflow),
        ("CI004", "Checkout credentials explicitly persisted", Medium, Automation, "Set persist-credentials: false unless later steps explicitly require authenticated Git operations.", r"(?m)^[ \t]*persist-credentials:[ \t]*true\b", Workflow),
        ("CI005", "Untrusted event data interpolated into workflow", High, Automation, "Pass untrusted event data through an environment variable and quote it. Check whether this expression reaches a shell or another interpreter.", r"\$\{\{[ \t]*github\.event\.(?:issue|pull_request|comment|discussion)\.(?:title|body|head\.ref)[ \t]*\}\}", Workflow),
        ("RUN001", "Broad container build-context copy", Medium, Runtime, "Prefer explicit COPY sources and review .dockerignore. A broad copy can include local credentials and private artifacts.", r"(?im)^[ \t]*(?:ADD|COPY)[ \t]+(?:--[^\s]+[ \t]+)*\.[ \t]+", Docker),
        ("RUN002", "Privileged container enabled", High, Runtime, "Remove privileged mode and grant only individually justified capabilities. Apply runtime confinement.", r"(?m)^[ \t]*privileged:[ \t]*true\b", Config),
        ("RUN003", "Service binds every interface", Medium, Runtime, "Bind to loopback unless external access is required. Verify firewall rules, authentication, and deployment context.", r#"(?im)^[ \t]*(?:host|bind|listen|address)[ \t]*[:=][ \t]*["']?(?:0\.0\.0\.0|::)"#, Config),
        ("RUN004", "TLS certificate verification disabled", High, Runtime, "Enable certificate and hostname verification; install an appropriate trust root instead of bypassing validation.", r#"(?i)\b(?:verify_ssl|ssl_verify|verify_certs|tls_verify|rejectUnauthorized)[ \t]*[:=][ \t]*(?:false|0)\b|\bNODE_TLS_REJECT_UNAUTHORIZED[ \t]*=[ \t]*["']?0"#, Any),
        ("RUN005", "Debug mode enabled in configuration", Medium, Runtime, "Verify deployment context and disable debug mode on exposed services. This heuristic does not establish production use.", r#"(?im)^[ \t]*(?:DEBUG|FLASK_DEBUG)[ \t]*[:=][ \t]*["']?(?:true|1)\b"#, Config),
        ("RUN006", "SSH root password login permitted", High, Runtime, "Disable direct root login; use individually attributable accounts and strong authentication.", r"(?m)^[ \t]*PermitRootLogin[ \t]+yes\b", Any),
        ("PRV001", "Personal home-directory path", Low, Privacy, "Replace user-specific absolute paths with relative or environment-based paths before publishing artifacts.", r#"(?:[A-Za-z]:\\Users\\[^\\\s"'<>]+|/(?:Users|home)/[^/\s"'<>]+)"#, Any),
    ];
    for (id, title, severity, category, remediation, pattern, scope) in definitions {
        let mut rule = pattern_rule(id, title, severity, category, remediation, pattern, scope)?;
        if let Detector::Content { capture, entropy, unpinned, .. } = &mut rule.detector {
            if ["SEC008", "SEC009", "SEC012", "CI002"].contains(&id) { *capture = 1; }
            if id == "SEC009" { *entropy = Some(3.5); }
            if id == "SEC012" { *entropy = Some(3.3); }
            *unpinned = id == "CI002";
        }
        rules.push(rule);
    }
    let artifacts = [
        ("ART001", "Environment file may contain sensitive settings", Medium, Artifact, "Review contents before distribution; keep real environment files out of source control and use a sanitized template.", Detector::Env),
        ("ART002", "Infrastructure state artifact", High, Artifact, "Treat state as sensitive; use an encrypted access-controlled backend and exclude local state from distribution.", Detector::State),
        ("ART003", "Desktop metadata artifact", Low, Privacy, "Remove desktop metadata before publishing; it can reveal directory and environment details.", Detector::DesktopMetadata),
        ("ART004", "Private key or credential-store artifact", High, Artifact, "Verify ownership and necessity, restrict access, and keep credential stores outside distributable source trees.", Detector::KeyStore),
        ("PRV002", "Sensitive file accessible to group or others", High, Privacy, "On Unix, restrict sensitive files to their owner (typically mode 0600) and review directory permissions and ACLs.", Detector::Permissions),
    ];
    for (id, title, severity, category, remediation, detector) in artifacts {
        rules.push(Rule { info: RuleInfo { id: id.into(), title: title.into(), severity, category, remediation: remediation.into() }, detector, scope: Any, path: None });
    }
    Ok(rules)
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() { return 0.0; }
    let mut frequencies = [0u64; 256];
    for byte in bytes { frequencies[*byte as usize] += 1; }
    frequencies.iter().filter(|count| **count != 0).map(|count| {
        let probability = *count as f64 / bytes.len() as f64;
        -probability * probability.log2()
    }).sum()
}

/// Only exact, well-known placeholders are suppressed; no substring allowlisting.
fn is_placeholder(value: &str) -> bool {
    ["password", "changeme", "example", "your_password", "your_token_here", "AKIAIOSFODNN7EXAMPLE"].iter().any(|p| value.eq_ignore_ascii_case(p))
}

fn is_pinned_action(value: &str) -> bool {
    let value = value.trim_matches(['\'', '"']);
    if value.starts_with("./") { return true; }
    if value.starts_with("docker://") {
        return value.rsplit_once("@sha256:").is_some_and(|(_, hash)| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    value.rsplit_once('@').is_some_and(|(_, hash)| hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn action_pinning() {
        assert!(is_pinned_action("./local-action"));
        assert!(is_pinned_action(&format!("owner/action@{}", "a".repeat(40))));
        assert!(is_pinned_action(&format!("docker://image@sha256:{}", "a".repeat(64))));
        assert!(!is_pinned_action("owner/action@v4"));
        assert!(!is_pinned_action("docker://image:latest"));
        assert!(!is_pinned_action("owner/action@abc123"));
    }

    #[test]
    fn entropy_examples() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaaaaaa"), 0.0);
        assert!((shannon_entropy(b"abcd") - 2.0).abs() < 1e-10);
    }

    proptest! {
        #[test]
        fn entropy_is_bounded(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let entropy = shannon_entropy(&bytes);
            prop_assert!((0.0..=8.00000001).contains(&entropy));
        }
    }
}
