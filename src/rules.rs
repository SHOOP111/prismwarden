use crate::config::{Config, CustomRule, path_glob};
use crate::model::{Category, Finding, Severity, fingerprint};
use anyhow::{Result, ensure};
use globset::GlobMatcher;
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

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    Any,
    Workflow,
    Docker,
    Config,
}

#[derive(Clone)]
enum Detector {
    Content {
        regex: Regex,
        prefilter: String,
        capture: usize,
        entropy: Option<f64>,
        unpinned: bool,
        assigned: bool,
    },
    Env,
    State,
    DesktopMetadata,
    KeyStore,
    Permissions,
}

#[derive(Clone)]
struct Rule {
    info: RuleInfo,
    detector: Detector,
    scope: Scope,
    path: Option<GlobMatcher>,
}

#[derive(Clone)]
pub struct RulePack {
    rules: Vec<Rule>,
    prefilter: RegexSet,
    indices: Vec<usize>,
    known: BTreeSet<String>,
    pub digest: String,
}

impl RulePack {
    pub fn compile(config: &Config) -> Result<Self> {
        config.validate()?;
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
        rules.sort_by(|a, b| a.info.id.cmp(&b.info.id));
        let digest = pack_digest(config, &rules)?;
        rules.retain(|r| !config.disable_rules.contains(&r.info.id));
        let indices: Vec<_> = rules
            .iter()
            .enumerate()
            .filter_map(|(i, r)| matches!(r.detector, Detector::Content { .. }).then_some(i))
            .collect();
        let patterns: Vec<_> = indices
            .iter()
            .map(|i| match &rules[*i].detector {
                Detector::Content { prefilter, .. } => prefilter.as_str(),
                _ => unreachable!(),
            })
            .collect();
        let prefilter = RegexSetBuilder::new(patterns)
            .size_limit(32 * 1024 * 1024)
            .build()
            .map_err(|_| anyhow::anyhow!("combined rule patterns exceed regex limits"))?;
        Ok(Self {
            rules,
            prefilter,
            indices,
            known,
            digest,
        })
    }

    pub fn catalog(&self) -> Vec<RuleInfo> {
        self.rules.iter().map(|r| r.info.clone()).collect()
    }

    pub fn known_ids(&self) -> &BTreeSet<String> {
        &self.known
    }

    /// Returns false if the caller's per-file candidate budget was exhausted.
    pub fn inspect_content(
        &self,
        path: &str,
        text: &str,
        mut emit: impl FnMut(Finding) -> bool,
    ) -> bool {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        // Count raw matches as well as emitted findings: optional/empty captures,
        // placeholders and entropy rejects must not bypass the CPU-work ceiling.
        let mut attempts = 0usize;
        for index in self.prefilter.matches(text) {
            let rule = &self.rules[self.indices[index]];
            if !rule.applies(path) {
                continue;
            }
            let Detector::Content {
                regex,
                capture,
                entropy,
                unpinned,
                assigned,
                ..
            } = &rule.detector
            else {
                continue;
            };
            // Captures are monotonic within one rule. Advance a Unicode cursor
            // once instead of building a line index or rescanning long lines.
            let (mut offset, mut line, mut column, mut previous_cr) = (0, 1, 1, false);
            for captures in regex.captures_iter(text) {
                attempts += 1;
                if attempts > 32_768 {
                    return false;
                }
                let Some(matched) = captures.get(*capture) else {
                    continue;
                };
                let value = matched.as_str();
                if value.is_empty() {
                    continue;
                }
                if *unpinned && is_pinned_action(value) {
                    continue;
                }
                if *assigned
                    && is_environment_reference(value)
                    && !text[..matched.start()].ends_with(['\'', '"'])
                {
                    continue;
                }
                if rule.info.category == Category::Secret && is_placeholder(value) {
                    continue;
                }
                if entropy.is_some_and(|minimum| shannon_entropy(value.as_bytes()) < minimum) {
                    continue;
                }
                for ch in text[offset..matched.start()].chars() {
                    match ch {
                        '\r' => {
                            line += 1;
                            column = 1;
                        }
                        '\n' => {
                            line += usize::from(!previous_cr);
                            column = 1;
                        }
                        _ => column += 1,
                    }
                    previous_cr = ch == '\r';
                }
                offset = matched.start();
                let finding = rule.finding(path, line, column, value.as_bytes());
                if !emit(finding) {
                    return false;
                }
            }
        }
        true
    }

    pub fn inspect_path(
        &self,
        path: &str,
        unix_mode: Option<u32>,
        mut emit: impl FnMut(Finding) -> bool,
    ) -> bool {
        let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
        let sensitive_env = (name == ".env" || name.starts_with(".env."))
            && !["example", "sample", "template", "dist"]
                .iter()
                .any(|suffix| {
                    name.rsplit_once('.')
                        .is_some_and(|(_, last)| last == *suffix)
                });
        let key_store = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"].contains(&name.as_str())
            || [".p12", ".pfx", ".kdbx"]
                .iter()
                .any(|suffix| name.ends_with(suffix));
        for rule in &self.rules {
            let hit = match rule.detector {
                Detector::Env => sensitive_env,
                Detector::State => name.ends_with(".tfstate") || name.ends_with(".tfstate.backup"),
                Detector::DesktopMetadata => {
                    [".ds_store", "thumbs.db", "desktop.ini"].contains(&name.as_str())
                }
                Detector::KeyStore => key_store,
                Detector::Permissions => {
                    (sensitive_env || key_store) && unix_mode.is_some_and(|mode| mode & 0o077 != 0)
                }
                Detector::Content { .. } => false,
            };
            if hit && !emit(rule.finding(path, 1, 1, rule.info.id.as_bytes())) {
                return false;
            }
        }
        true
    }
}

/// Length-framed diagnostic provenance, including non-regex detector settings.
/// This is not a code signature; retain the artifact's commit for exact identity.
fn pack_digest(config: &Config, rules: &[Rule]) -> Result<String> {
    use serde_json::json;
    let mut digest = blake3::Hasher::new_derive_key("prismwarden.rulepack.v2");
    for part in [
        env!("CARGO_PKG_VERSION").as_bytes().to_vec(),
        serde_json::to_vec(config)?,
    ] {
        digest.update(&(part.len() as u64).to_le_bytes());
        digest.update(&part);
    }
    for rule in rules {
        let detector = match &rule.detector {
            Detector::Content {
                regex,
                prefilter,
                capture,
                entropy,
                unpinned,
                assigned,
            } => json!({
                "kind": "content", "pattern": regex.as_str(), "prefilter": prefilter,
                "capture": capture, "entropy": entropy, "unpinned": unpinned, "assigned": assigned,
            }),
            Detector::Env => json!("env"),
            Detector::State => json!("state"),
            Detector::DesktopMetadata => json!("desktop_metadata"),
            Detector::KeyStore => json!("key_store"),
            Detector::Permissions => json!("permissions"),
        };
        let part = serde_json::to_vec(&json!({
            "info": rule.info, "scope": rule.scope, "detector": detector,
            "path_globs": "literal-separator/backslash-escape",
        }))?;
        digest.update(&(part.len() as u64).to_le_bytes());
        digest.update(&part);
    }
    Ok(digest.finalize().to_hex().to_string())
}

impl Rule {
    fn applies(&self, path: &str) -> bool {
        if self.path.as_ref().is_some_and(|g| !g.is_match(path)) {
            return false;
        }
        match self.scope {
            Scope::Any => true,
            Scope::Workflow => {
                path.starts_with(".github/workflows/")
                    && (path.ends_with(".yml") || path.ends_with(".yaml"))
            }
            Scope::Docker => path.rsplit('/').next().is_some_and(|n| {
                n.eq_ignore_ascii_case("dockerfile")
                    || n.to_ascii_lowercase().starts_with("dockerfile.")
            }),
            Scope::Config => {
                let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
                [
                    ".yml",
                    ".yaml",
                    ".toml",
                    ".ini",
                    ".conf",
                    ".env",
                    ".json",
                    ".properties",
                ]
                .iter()
                .any(|s| name.ends_with(s))
                    || name == ".env"
                    || name.starts_with(".env.")
            }
        }
    }

    fn finding(&self, path: &str, line: usize, column: usize, evidence: &[u8]) -> Finding {
        Finding {
            path: path.to_owned(),
            line,
            column,
            rule_id: self.info.id.clone(),
            fingerprint: fingerprint(&self.info.id, path, evidence),
            severity: self.info.severity,
            category: self.info.category,
            title: self.info.title.clone(),
            remediation: self.info.remediation.clone(),
        }
    }
}

fn pattern_rule(
    id: &str,
    title: &str,
    severity: Severity,
    category: Category,
    remediation: &str,
    pattern: &str,
    scope: Scope,
) -> Result<Rule> {
    let regex = RegexBuilder::new(pattern)
        .size_limit(2 * 1024 * 1024)
        .build()
        .map_err(|_| anyhow::anyhow!("invalid or oversized rule regex"))?;
    Ok(Rule {
        info: RuleInfo {
            id: id.into(),
            title: title.into(),
            severity,
            category,
            remediation: remediation.into(),
        },
        detector: Detector::Content {
            regex,
            prefilter: pattern.into(),
            capture: 0,
            entropy: None,
            unpinned: false,
            assigned: false,
        },
        scope,
        path: None,
    })
}

fn compile_custom(custom: &CustomRule) -> Result<Rule> {
    ensure!(
        custom.id.len() >= 3
            && custom.id.len() <= 32
            && custom.id.starts_with(|c: char| c.is_ascii_uppercase())
            && custom
                .id
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_' || c == b'-'),
        "custom rule IDs must be 3-32 uppercase ASCII identifier characters"
    );
    ensure!(
        custom.pattern.len() <= 4096,
        "custom regex exceeds 4096 bytes"
    );
    ensure!(
        !custom.title.trim().is_empty()
            && custom.title.len() <= 160
            && !custom.remediation.trim().is_empty()
            && custom.remediation.len() <= 1024,
        "custom rules require a title (<=160 bytes) and remediation (<=1024 bytes)"
    );
    ensure!(
        custom
            .min_entropy
            .is_none_or(|e| e.is_finite() && (0.0..=8.0).contains(&e)),
        "entropy threshold must be between 0 and 8"
    );
    let mut rule = pattern_rule(
        &custom.id,
        &custom.title,
        custom.severity,
        custom.category,
        &custom.remediation,
        &custom.pattern,
        Scope::Any,
    )?;
    if let Detector::Content {
        regex,
        capture,
        entropy,
        ..
    } = &mut rule.detector
    {
        ensure!(
            !regex.is_match(""),
            "custom regex must not match an empty string"
        );
        ensure!(
            custom.capture < regex.captures_len(),
            "custom rule capture index does not exist"
        );
        *capture = custom.capture;
        *entropy = custom.min_entropy;
    }
    rule.path = custom
        .path
        .as_ref()
        .map(|p| {
            path_glob(p)
                .map(|g| g.compile_matcher())
                .map_err(|_| anyhow::anyhow!("invalid custom rule path glob"))
        })
        .transpose()?;
    Ok(rule)
}

fn builtins() -> Result<Vec<Rule>> {
    use Category::*;
    use Scope::*;
    use Severity::*;
    let rotate = "Revoke and rotate the credential; remove it from the tree and review history and access logs. Use a secret manager.";
    let mut rules = Vec::new();
    let definitions = [
        (
            "SEC001",
            "Private key material",
            Critical,
            Secret,
            rotate,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            Any,
        ),
        (
            "SEC002",
            "GitHub token-shaped credential",
            High,
            Secret,
            rotate,
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b",
            Any,
        ),
        (
            "SEC003",
            "AWS access key identifier",
            High,
            Secret,
            "Locate the paired secret, review IAM access, and rotate the key. An identifier alone does not prove usable access.",
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
            Any,
        ),
        (
            "SEC004",
            "Slack token-shaped credential",
            High,
            Secret,
            rotate,
            r"\bxox[baprs]-[A-Za-z0-9-]{20,200}\b",
            Any,
        ),
        (
            "SEC005",
            "Live Stripe secret-shaped key",
            High,
            Secret,
            rotate,
            r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,200}\b",
            Any,
        ),
        (
            "SEC006",
            "Google API key-shaped value",
            High,
            Secret,
            "Restrict the API key by application and API, review usage, and rotate if exposed.",
            r"\bAIza[A-Za-z0-9_-]{35}\b",
            Any,
        ),
        (
            "SEC007",
            "JWT-shaped token",
            Medium,
            Secret,
            "Determine whether the token grants access or exposes claims. Revoke its session if sensitive; never paste it into an online decoder.",
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            Any,
        ),
        (
            "SEC008",
            "Credentials embedded in a URL",
            High,
            Secret,
            rotate,
            r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|https?)://[^\s:/@"']{1,64}:([^\s@/"']{3,128})@"#,
            Any,
        ),
        (
            "SEC009",
            "High-entropy assigned secret",
            High,
            Secret,
            rotate,
            r#"(?im)(?:^[ \t]*(?:(?:export|const|let|var)[ \t]+|-[ \t]*)?|[,{][ \t]*)["']?(?:[A-Za-z0-9_.-]*(?:password|passwd|api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|aws_secret_access_key))["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9/+_=.!@#$%^&*\-]{16,160})"#,
            Any,
        ),
        (
            "SEC010",
            "PyPI upload token-shaped value",
            High,
            Secret,
            rotate,
            r"\bpypi-[A-Za-z0-9_-]{50,300}\b",
            Any,
        ),
        (
            "SEC011",
            "npm token-shaped credential",
            High,
            Secret,
            rotate,
            r"\bnpm_[A-Za-z0-9]{36}\b",
            Any,
        ),
        (
            "SEC012",
            "Hard-coded bearer authorization",
            High,
            Secret,
            rotate,
            r#"(?i)\bauthorization["']?[ \t]*[:=][ \t]*["']?Bearer[ \t]+([A-Za-z0-9._~+/-]{20,300}=*)"#,
            Any,
        ),
        (
            "CI001",
            "Workflow grants write-all permissions",
            High,
            Automation,
            "Set top-level permissions to contents: read and grant minimal permissions only to the jobs that need them.",
            r#"(?mR)^[ \t]*["']?permissions["']?:[ \t]*["']?write-all["']?[ \t]*(?:#.*)?$"#,
            Workflow,
        ),
        (
            "CI002",
            "Action reference is not immutably pinned",
            Medium,
            Automation,
            "Pin external actions to a reviewed full 40-character commit SHA; pin Docker actions by sha256 digest.",
            r#"(?m)^[ \t]*-?[ \t]*["']?uses["']?:[ \t]*([^\s#]+)"#,
            Workflow,
        ),
        (
            "CI003",
            "Privileged pull request trigger",
            High,
            Automation,
            "Review pull_request_target carefully. Never run untrusted pull-request code or interpolate untrusted input in a privileged job.",
            r"\bpull_request_target\b",
            Workflow,
        ),
        (
            "CI004",
            "Checkout credentials explicitly persisted",
            Medium,
            Automation,
            "Set persist-credentials: false unless later steps explicitly require authenticated Git operations.",
            r#"(?im)^[ \t]*["']?persist-credentials["']?:[ \t]*["']?true\b"#,
            Workflow,
        ),
        (
            "CI005",
            "Untrusted event data interpolated into workflow",
            High,
            Automation,
            "Pass untrusted event data through an environment variable and quote it. Check whether this expression reaches a shell or another interpreter.",
            r"\$\{\{[ \t]*(?:github\.head_ref\b|github\.event\.(?:(?:issue|pull_request|comment|discussion)\.(?:title|body|head\.(?:ref|label))|(?:head_commit|commits\[[^\]\r\n]{1,32}\])\.(?:message|author\.(?:name|email))))\b",
            Workflow,
        ),
        (
            "RUN001",
            "Broad container build-context copy",
            Medium,
            Runtime,
            "Prefer explicit COPY sources and review .dockerignore. A broad copy can include local credentials and private artifacts.",
            r#"(?im)^[ \t]*(?:ADD|COPY)[ \t]+(?:--[^\s]+[ \t]+)*(?:\./?[ \t]+|\[[ \t]*"\./?"[ \t]*,)"#,
            Docker,
        ),
        (
            "RUN002",
            "Privileged container enabled",
            High,
            Runtime,
            "Remove privileged mode and grant only individually justified capabilities. Apply runtime confinement.",
            r#"(?im)(?:^|[,{])[ \t]*["']?privileged["']?:[ \t]*["']?true\b"#,
            Config,
        ),
        (
            "RUN003",
            "Service binds every interface",
            Medium,
            Runtime,
            "Bind to loopback unless external access is required. Verify firewall rules, authentication, and deployment context.",
            r#"(?im)(?:^|[,{])[ \t]*["']?(?:host|bind|listen|address)["']?[ \t]*[:=][ \t]*["']?(?:0\.0\.0\.0(?::[0-9]{1,5})?|\[::\](?::[0-9]{1,5})?|::)(?:["'\s,}#]|$)"#,
            Config,
        ),
        (
            "RUN004",
            "TLS certificate verification disabled",
            High,
            Runtime,
            "Enable certificate and hostname verification; install an appropriate trust root instead of bypassing validation.",
            r#"(?i)\b(?:verify_ssl|ssl_verify|verify_certs|tls_verify|rejectUnauthorized)["']?[ \t]*[:=][ \t]*["']?(?:false|0)\b|\bNODE_TLS_REJECT_UNAUTHORIZED["']?[ \t]*[:=][ \t]*["']?0\b"#,
            Any,
        ),
        (
            "RUN005",
            "Debug mode enabled in configuration",
            Medium,
            Runtime,
            "Verify deployment context and disable debug mode on exposed services. This heuristic does not establish production use.",
            r#"(?im)(?:^|[,{])[ \t]*["']?(?:DEBUG|FLASK_DEBUG)["']?[ \t]*[:=][ \t]*["']?(?:true|1)\b"#,
            Config,
        ),
        (
            "RUN006",
            "SSH root password login permitted",
            High,
            Runtime,
            "Disable direct root login; use individually attributable accounts and strong authentication.",
            r"(?m)^[ \t]*PermitRootLogin[ \t]+yes\b",
            Any,
        ),
        (
            "PRV001",
            "Personal home-directory path",
            Low,
            Privacy,
            "Replace user-specific absolute paths with relative or environment-based paths before publishing artifacts.",
            r#"(?:[A-Za-z]:\\Users\\[^\\\s"'<>]+|/(?:Users|home)/[^/\s"'<>]+)"#,
            Any,
        ),
    ];
    for (id, title, severity, category, remediation, pattern, scope) in definitions {
        let mut rule = pattern_rule(id, title, severity, category, remediation, pattern, scope)?;
        if let Detector::Content {
            prefilter,
            capture,
            entropy,
            unpinned,
            assigned,
            ..
        } = &mut rule.detector
        {
            // Built-in boundary assertions are not literal escapes or inside
            // character classes. Removing them only broadens the shortlist;
            // the original Unicode-aware regex still decides every finding.
            // This avoids a RegexSet Unicode-boundary fallback on non-ASCII text.
            *prefilter = pattern.replace(r"\b", "");
            if ["SEC008", "SEC009", "SEC012", "CI002"].contains(&id) {
                *capture = 1;
            }
            if id == "SEC009" {
                *entropy = Some(3.5);
            }
            if id == "SEC012" {
                *entropy = Some(3.3);
            }
            *unpinned = id == "CI002";
            *assigned = id == "SEC009";
        }
        rules.push(rule);
    }
    let artifacts = [
        (
            "ART001",
            "Environment file may contain sensitive settings",
            Medium,
            Artifact,
            "Review contents before distribution; keep real environment files out of source control and use a sanitized template.",
            Detector::Env,
        ),
        (
            "ART002",
            "Infrastructure state artifact",
            High,
            Artifact,
            "Treat state as sensitive; use an encrypted access-controlled backend and exclude local state from distribution.",
            Detector::State,
        ),
        (
            "ART003",
            "Desktop metadata artifact",
            Low,
            Privacy,
            "Remove desktop metadata before publishing; it can reveal directory and environment details.",
            Detector::DesktopMetadata,
        ),
        (
            "ART004",
            "Private key or credential-store artifact",
            High,
            Artifact,
            "Verify ownership and necessity, restrict access, and keep credential stores outside distributable source trees.",
            Detector::KeyStore,
        ),
        (
            "PRV002",
            "Sensitive file accessible to group or others",
            High,
            Privacy,
            "On Unix, restrict sensitive files to their owner (typically mode 0600) and review directory permissions and ACLs.",
            Detector::Permissions,
        ),
    ];
    for (id, title, severity, category, remediation, detector) in artifacts {
        rules.push(Rule {
            info: RuleInfo {
                id: id.into(),
                title: title.into(),
                severity,
                category,
                remediation: remediation.into(),
            },
            detector,
            scope: Any,
            path: None,
        });
    }
    Ok(rules)
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut frequencies = [0u64; 256];
    for byte in bytes {
        frequencies[*byte as usize] += 1;
    }
    frequencies
        .iter()
        .filter(|count| **count != 0)
        .map(|count| {
            let probability = *count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

/// Only exact, well-known placeholders are suppressed; no substring allowlisting.
fn is_placeholder(value: &str) -> bool {
    [
        "password",
        "changeme",
        "example",
        "your_password",
        "your_token_here",
        "AKIAIOSFODNN7EXAMPLE",
    ]
    .iter()
    .any(|p| value.eq_ignore_ascii_case(p))
}

/// Exclude only well-known, unquoted environment-property expressions, not
/// strings containing "env" or quoted literal credentials with these prefixes.
fn is_environment_reference(value: &str) -> bool {
    ["process.env.", "import.meta.env."]
        .iter()
        .filter_map(|prefix| value.strip_prefix(prefix))
        .any(|property| {
            property.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
                && property
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
        })
}

fn is_pinned_action(value: &str) -> bool {
    let value = value.trim_matches(['\'', '"']);
    if value.starts_with("./") {
        return true;
    }
    if value.starts_with("docker://") {
        return value.rsplit_once("@sha256:").is_some_and(|(_, hash)| {
            hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
        });
    }
    value
        .rsplit_once('@')
        .is_some_and(|(_, hash)| hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn action_pinning() {
        assert!(is_pinned_action("./local-action"));
        assert!(is_pinned_action(&format!(
            "owner/action@{}",
            "a".repeat(40)
        )));
        assert!(is_pinned_action(&format!(
            "docker://image@sha256:{}",
            "a".repeat(64)
        )));
        assert!(!is_pinned_action("owner/action@v4"));
        assert!(!is_pinned_action("docker://image:latest"));
        assert!(!is_pinned_action("owner/action@abc123"));
    }

    #[test]
    fn digest_binds_scope_capture_entropy_and_pinning() {
        let config = Config::default();
        let original = builtins().unwrap();
        let digest = pack_digest(&config, &original).unwrap();
        for change in 0..7 {
            let mut rules = original.clone();
            if change == 0 {
                rules[0].scope = Scope::Workflow;
            } else if change == 4 {
                rules[0].detector = Detector::Permissions;
            } else if let Detector::Content {
                prefilter,
                capture,
                entropy,
                unpinned,
                assigned,
                ..
            } = &mut rules[0].detector
            {
                match change {
                    1 => *capture = 1,
                    2 => *entropy = Some(3.0),
                    3 => *unpinned = true,
                    5 => *assigned = true,
                    _ => prefilter.clear(),
                }
            }
            assert_ne!(digest, pack_digest(&config, &rules).unwrap());
        }
        assert_eq!(digest, pack_digest(&config, &original).unwrap());
    }

    #[test]
    fn entropy_examples() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaaaaaa"), 0.0);
        assert!((shannon_entropy(b"abcd") - 2.0).abs() < 1e-10);
    }

    static REFERENCE_PACKS: std::sync::LazyLock<(RulePack, RulePack)> =
        std::sync::LazyLock::new(|| {
            let optimized = RulePack::compile(&Config::default()).unwrap();
            let mut reference = optimized.clone();
            reference.prefilter = RegexSetBuilder::new(reference.indices.iter().map(|index| {
                match &reference.rules[*index].detector {
                    Detector::Content { regex, .. } => regex.as_str(),
                    _ => unreachable!(),
                }
            }))
            .size_limit(32 * 1024 * 1024)
            .build()
            .unwrap();
            (optimized, reference)
        });

    #[test]
    fn custom_unicode_boundaries_are_not_rewritten() {
        let config = Config {
            rules: vec![CustomRule {
                id: "ORG001".into(),
                title: "Unicode marker".into(),
                remediation: "Review".into(),
                severity: Severity::Low,
                category: Category::Privacy,
                pattern: r"\bλ\b".into(),
                capture: 0,
                min_entropy: None,
                path: None,
            }],
            ..Config::default()
        };
        let pack = RulePack::compile(&config).unwrap();
        let mut found = false;
        assert!(pack.inspect_content("source.txt", " λ ", |finding| {
            found |= finding.rule_id == "ORG001";
            true
        }));
        assert!(found);
    }

    proptest! {
        #[test]
        fn optimized_prefilter_preserves_unicode_findings_and_budgets(
            prefix in proptest::collection::vec(any::<char>(), 0..256),
            budget in 0usize..16,
        ) {
            let prefix: String = prefix.into_iter().collect();
            let token = format!("ghp_{}", "A".repeat(36));
            let text = format!("{prefix}\nλ{token} λ {token}\r\n{token}\n{prefix}");
            let (optimized, reference) = &*REFERENCE_PACKS;
            let mut actual = Vec::new();
            let mut expected = Vec::new();
            let complete = optimized.inspect_content("source.txt", &text, |finding| {
                actual.push(finding);
                actual.len() <= budget
            });
            let reference_complete = reference.inspect_content("source.txt", &text, |finding| {
                expected.push(finding);
                expected.len() <= budget
            });
            prop_assert_eq!(complete, reference_complete);
            prop_assert_eq!(actual, expected);
        }

        #[test]
        fn entropy_is_bounded(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let entropy = shannon_entropy(&bytes);
            prop_assert!((0.0..=8.00000001).contains(&entropy));
        }
    }
}
