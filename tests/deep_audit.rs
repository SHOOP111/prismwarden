//! Deep-audit regressions. All execution belongs on GitHub-hosted runners.
use prismwarden::baseline::Baseline;
use prismwarden::config::{AllowEntry, Config, CustomRule, Policy};
use prismwarden::model::{Category, Notice, Severity};
use prismwarden::output::{self, Format};
use prismwarden::rules::RulePack;
use prismwarden::{Report, ScanOptions, scan};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

static RULES: LazyLock<RulePack> = LazyLock::new(|| RulePack::compile(&Config::default()).unwrap());

fn options(root: &Path) -> ScanOptions {
    ScanOptions { root: root.into(), threads: 2, ..ScanOptions::default() }
}

fn report(root: &Path) -> Report {
    scan(&options(root), &Config::default(), &Baseline::empty()).unwrap()
}

fn detects(id: &str, path: &str, text: &str) -> bool {
    let mut found = false;
    assert!(RULES.inspect_content(path, text, |finding| {
        found |= finding.rule_id == id;
        true
    }));
    found
}

#[test]
fn policy_globs_are_directory_aware_on_every_platform() {
    let mut config = Config {
        exclude: vec!["*.bin".into(), "assets/*".into()],
        allow: vec![AllowEntry {
            rule: "SEC002".into(), path: "fixtures/*.txt".into(), reason: "Reviewed fixtures".into(),
        }],
        ..Config::default()
    };
    let policy = Policy::compile(&config, RULES.known_ids()).unwrap();
    assert!(policy.excludes.is_match("image.bin"));
    assert!(!policy.excludes.is_match("nested/image.bin"));
    assert!(policy.excludes.is_match("assets/image.png"));
    assert!(!policy.excludes.is_match("assets/nested/image.png"));
    assert!(policy.allows("SEC002", "fixtures/token.txt"));
    assert!(!policy.allows("SEC002", "fixtures/nested/token.txt"));
    assert!(!policy.allows("SEC001", "fixtures/token.txt"));
    config.exclude = vec!["**/*.bin".into()];
    config.allow[0].path = "fixtures/**/*.txt".into();
    let policy = Policy::compile(&config, RULES.known_ids()).unwrap();
    assert!(policy.excludes.is_match("image.bin"));
    assert!(policy.excludes.is_match("nested/image.bin"));
    assert!(policy.allows("SEC002", "fixtures/token.txt"));
    assert!(policy.allows("SEC002", "fixtures/nested/token.txt"));
}

#[test]
fn glob_backslash_escaping_is_platform_independent() {
    let config = Config { exclude: vec![r"literal\*.txt".into()], ..Config::default() };
    let policy = Policy::compile(&config, RULES.known_ids()).unwrap();
    assert!(policy.excludes.is_match("literal*.txt"));
    assert!(!policy.excludes.is_match("literal-secret.txt"));
}

#[test]
fn custom_path_globs_use_the_same_semantics_as_policy() {
    let config = Config {
        rules: vec![CustomRule {
            id: "ORG001".into(), title: "Internal marker".into(), remediation: "Review".into(),
            severity: Severity::Low, category: Category::Privacy, pattern: "INTERNAL".into(),
            capture: 0, min_entropy: None, path: Some("*.txt".into()),
        }],
        ..Config::default()
    };
    let rules = RulePack::compile(&config).unwrap();
    for (path, count) in [("root.txt", 1), ("nested/file.txt", 0), ("root.rs", 0)] {
        let mut actual = 0;
        assert!(rules.inspect_content(path, "INTERNAL", |_| { actual += 1; true }));
        assert_eq!(actual, count, "{path}");
    }
}

#[test]
fn no_ignore_bypasses_both_git_and_custom_ignore_but_not_policy_or_pruning() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join(".gitignore"), "git.txt\n").unwrap();
    fs::write(root.path().join(".prismwardenignore"), "custom.txt\n").unwrap();
    fs::create_dir(root.path().join("target")).unwrap();
    for name in ["git.txt", "custom.txt", "excluded.txt", "target/generated.txt"] {
        fs::write(root.path().join(name), format!("ghp_{}", "A".repeat(36))).unwrap();
    }
    let config = Config { exclude: vec!["excluded.txt".into()], ..Config::default() };
    let mut options = options(root.path());
    let default = scan(&options, &config, &Baseline::empty()).unwrap();
    assert!(default.complete && default.findings.is_empty());
    options.include_ignored = true;
    let included = scan(&options, &config, &Baseline::empty()).unwrap();
    assert_eq!(included.findings.len(), 1);
    options.include_ignored = false;
    options.no_ignore = true;
    let full = scan(&options, &config, &Baseline::empty()).unwrap();
    assert!(full.complete);
    assert_eq!(full.findings.len(), 2);
    assert!(full.scope.no_ignore && full.scope.include_gitignored);
    assert!(full.findings.iter().all(|f| ["custom.txt", "git.txt"].contains(&f.path.as_str())));
    for format in [Format::Text, Format::Markdown] {
        let text = String::from_utf8(output::render(&full, format).unwrap()).unwrap();
        assert!(text.contains("target ignore files bypassed"));
    }
    assert_eq!(output::sarif(&full)["runs"][0]["properties"]["scope"]["no_ignore"], true);
}

#[test]
fn mixed_newlines_have_sarif_unicode_codepoint_coordinates() {
    let token = format!("ghp_{}", "A".repeat(36));
    let text = format!("\u{feff}λ {token}\rβ {token}\r\nγ {token}\nδ {token}");
    let mut actual = Vec::new();
    assert!(RULES.inspect_content("source.txt", &text, |f| {
        if f.rule_id == "SEC002" { actual.push((f.line, f.column)); }
        true
    }));
    assert_eq!(actual, [(1, 3), (2, 3), (3, 3), (4, 3)]);
}

#[test]
fn line_cursor_preserves_crlf_state_between_adjacent_custom_captures() {
    let config = Config {
        rules: vec![CustomRule {
            id: "ORG001".into(), title: "Newline marker".into(), remediation: "Review".into(),
            severity: Severity::Low, category: Category::Privacy, pattern: "[\\r\\nX]".into(),
            capture: 0, min_entropy: None, path: None,
        }],
        ..Config::default()
    };
    let rules = RulePack::compile(&config).unwrap();
    let mut actual = Vec::new();
    assert!(rules.inspect_content("file.txt", "\r\nX\rX", |f| {
        if f.rule_id == "ORG001" { actual.push((f.line, f.column)); }
        true
    }));
    assert_eq!(actual, [(1, 1), (2, 1), (2, 1), (2, 2), (3, 1)]);
}

#[test]
fn assigned_secret_detection_covers_common_names_and_compact_json() {
    let value = "aB3dE5fG7hI9jK1lM3nO5pQ7";
    for name in ["API_KEY", "apiKey", "clientSecret", "AWS_SECRET_ACCESS_KEY", "service.auth-token"] {
        for text in [
            format!("{name} = \"{value}\""),
            format!("const {name} = \"{value}\";"),
            format!("{{\"ordinary\":true,\"{name}\":\"{value}\"}}"),
            format!("  - {name}={value}"),
        ] {
            assert!(detects("SEC009", "source.txt", &text), "{name}");
        }
    }
    for text in [
        "PUBLIC_SETTING = abcdefghijklmnopqrstuvwxyz",
        "apiKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "apiKey = ${SECRET_MANAGER_VALUE}",
        "apiKey = process.env.SERVICE_API_KEY",
    ] {
        assert!(!detects("SEC009", "source.txt", text));
    }
}

#[test]
fn untrusted_workflow_expression_fallbacks_and_head_refs_are_reviewed() {
    let path = ".github/workflows/build.yml";
    for expression in [
        "github.event.issue.title", "github.event.issue.title || 'fallback'",
        "github.event.pull_request.head.ref", "github.event.pull_request.head.label",
        "github.head_ref", "github.head_ref || github.ref_name",
        "github.event.head_commit.message", "github.event.head_commit.author.email",
        "github.event.commits[0].message",
    ] {
        let text = format!("run: echo ${{{{ {expression} }}}}");
        assert!(detects("CI005", path, &text), "{expression}");
        assert!(!detects("CI005", "README.md", &text));
    }
    for expression in ["github.event.issue.number", "github.ref", "github.event.pull_request.head.sha"] {
        assert!(!detects("CI005", path, &format!("${{{{ {expression} }}}}")));
    }
}

#[test]
fn inconsistent_public_reports_cannot_create_baselines() {
    let root = tempfile::tempdir().unwrap();
    let original = report(root.path());
    assert!(Baseline::from_report(&original).is_ok());
    for change in 0..5 {
        let mut report = original.clone();
        match change {
            0 => report.schema_version = 99,
            1 => report.statistics.coverage_notices = 1,
            2 => report.statistics.findings_omitted = 1,
            3 => report.notices.push(Notice { path: ".".into(), code: "file_limit".into() }),
            _ => report.complete = false,
        }
        assert!(Baseline::from_report(&report).is_err());
    }
    fs::write(root.path().join("source.txt"), format!("ghp_{}", "A".repeat(36))).unwrap();
    let mut invalid = report(root.path());
    invalid.findings[0].fingerprint = "not-a-fingerprint".into();
    assert!(Baseline::from_report(&invalid).is_err());
}

#[test]
fn incomplete_report_roundtrips_preserve_policy_and_coverage_gates() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..600 {
        fs::write(root.path().join(format!("{index:04}.bin")), [0, 1]).unwrap();
    }
    let original = report(root.path());
    assert!(!original.complete);
    assert_eq!(original.statistics.coverage_notices, 600);
    assert_eq!(original.notices.len(), 512);
    assert_eq!(original.statistics.binary_files, 600);
    let parsed: Report = serde_json::from_slice(&output::render(&original, Format::Json).unwrap()).unwrap();
    assert_eq!(parsed.exit_code(None, false), 3);
    assert_eq!(parsed.exit_code(None, true), 0);
    assert!(Baseline::from_report(&parsed).is_err());
    let mut options = options(root.path());
    options.threads = 1;
    let serial = scan(&options, &Config::default(), &Baseline::empty()).unwrap();
    assert_eq!(serde_json::to_value(original).unwrap(), serde_json::to_value(serial).unwrap());
}

#[test]
fn invalid_policy_details_are_never_echoed_in_error_messages() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("policy.toml");
    let marker = "never-echo-this-private-detail";
    for body in [
        format!("exclude = ['[{marker}']"),
        format!("disable_rules = ['{marker}']"),
        format!("[severity]\n{marker} = 'unexpected'"),
    ] {
        fs::write(&path, body).unwrap();
        let error = Config::load(&path).and_then(|config| {
            let rules = RulePack::compile(&config)?;
            Policy::compile(&config, rules.known_ids()).map(|_| ())
        }).unwrap_err();
        assert!(!format!("{error:#}").contains(marker));
    }
}

#[cfg(windows)]
#[test]
fn directory_junctions_are_not_traversed() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), format!("ghp_{}", "A".repeat(36))).unwrap();
    let link = root.path().join("junction");
    let created = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"]).arg(&link).arg(outside.path()).output().unwrap();
    assert!(created.status.success(), "{}", String::from_utf8_lossy(&created.stderr));
    let report = report(root.path());
    assert!(report.complete && report.findings.is_empty());
    assert_eq!(report.statistics.symlinks_skipped, 1);
    fs::remove_dir(link).unwrap();
}
