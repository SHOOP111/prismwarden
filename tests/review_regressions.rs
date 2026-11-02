//! Targeted regressions for the repository hardening review; run on GitHub runners only.
use prismwarden::baseline::Baseline;
use prismwarden::config::{Config, CustomRule};
use prismwarden::model::{Category, Severity};
use prismwarden::output::{self, Format};
use prismwarden::rules::RulePack;
use prismwarden::{Report, ScanOptions, scan};
use std::fs;
use std::sync::LazyLock;

static RULES: LazyLock<RulePack> = LazyLock::new(|| RulePack::compile(&Config::default()).unwrap());

fn detects(id: &str, path: &str, text: &str) -> bool {
    let mut found = false;
    assert!(RULES.inspect_content(path, text, |f| {
        found |= f.rule_id == id;
        true
    }));
    found
}

fn options(root: &std::path::Path) -> ScanOptions {
    ScanOptions {
        root: root.into(),
        threads: 2,
        ..ScanOptions::default()
    }
}

fn scan_default(root: &std::path::Path) -> Report {
    scan(&options(root), &Config::default(), &Baseline::empty()).unwrap()
}

#[test]
fn excluded_directory_is_not_walked_or_charged_to_budgets() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("private")).unwrap();
    for i in 0..20 {
        fs::write(root.path().join(format!("private/{i}.bin")), [0, 1]).unwrap();
    }
    fs::write(root.path().join("visible.txt"), "ordinary").unwrap();
    let config = Config {
        exclude: vec!["private".into()],
        ..Config::default()
    };
    let mut options = options(root.path());
    options.max_files = 1;
    let report = scan(&options, &config, &Baseline::empty()).unwrap();
    assert!(report.complete, "{:?}", report.notices);
    assert_eq!(report.statistics.files_scanned, 1);
    assert_eq!(report.statistics.excluded_by_policy, 1);
}

#[test]
fn hard_pruning_applies_to_directories_not_regular_file_names() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("target"),
        format!("ghp_{}", "A".repeat(36)),
    )
    .unwrap();
    let report = scan_default(root.path());
    assert!(report.complete);
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn content_budgets_do_not_hide_sensitive_artifact_findings() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("terraform.tfstate"), "sensitive state").unwrap();
    for per_file in [true, false] {
        let mut options = options(root.path());
        if per_file {
            options.max_file_bytes = 1;
        } else {
            options.max_total_bytes = 1;
        }
        let report = scan(&options, &Config::default(), &Baseline::empty()).unwrap();
        assert!(!report.complete);
        assert!(report.findings.iter().any(|f| f.rule_id == "ART002"));
        assert_eq!(report.statistics.bytes_read, 0);
        assert_eq!(report.exit_code(Some(Severity::High), true), 1);
        assert_eq!(
            report.notices[0].code,
            if per_file {
                "oversized_file"
            } else {
                "byte_budget"
            }
        );
    }
}

#[test]
fn quoted_crlf_workflow_settings_and_immutable_actions() {
    let path = ".github/workflows/build.yml";
    for text in [
        "permissions: write-all\r\n",
        "'permissions': 'write-all'\r\n",
    ] {
        assert!(detects("CI001", path, text));
    }
    assert!(detects(
        "CI004",
        path,
        "\"persist-credentials\": \"true\"\r\n"
    ));
    assert!(detects("CI002", path, "- 'uses': 'owner/action@v4'\r\n"));
    assert!(!detects(
        "CI002",
        path,
        &format!("- 'uses': 'owner/action@{}'\r\n", "a".repeat(40))
    ));
}

#[test]
fn runtime_json_quotes_ipv6_and_address_boundaries() {
    assert!(detects("RUN002", "compose.JSON", r#"{"privileged": true}"#));
    assert!(detects(
        "RUN005",
        "server.json",
        r#"{"mode": "dev", "DEBUG": true}"#
    ));
    for address in ["0.0.0.0", "0.0.0.0:8080", "::", "[::]:8080"] {
        assert!(detects(
            "RUN003",
            "server.toml",
            &format!("host = \"{address}\"")
        ));
    }
    for address in ["::1", "::ffff:127.0.0.1", "0.0.0.01", "0.0.0.0.example"] {
        assert!(
            !detects("RUN003", "server.toml", &format!("host = \"{address}\"")),
            "{address}"
        );
    }
    let tls = ["{\"tls_", "verify\": false}"].concat();
    assert!(detects("RUN004", "client.json", &tls));
    assert!(!detects(
        "RUN004",
        "client.env",
        "NODE_TLS_REJECT_UNAUTHORIZED=01"
    ));
}

#[test]
fn docker_json_copy_and_exact_environment_template_suffixes() {
    for text in [
        "COPY ./ /app",
        "COPY [\".\", \"/app\"]",
        "ADD --chown=app [\"./\", \"/app\"]",
    ] {
        assert!(detects("RUN001", "Dockerfile", text));
    }
    assert!(!detects(
        "RUN001",
        "Dockerfile",
        "COPY [\"./src\", \"/app\"]"
    ));
    for (path, expected) in [
        (".env.example", false),
        (".env.dist", false),
        (".env.notexample", true),
        (".env.redisdist", true),
    ] {
        let mut found = false;
        RULES.inspect_path(path, None, |f| {
            found |= f.rule_id == "ART001";
            true
        });
        assert_eq!(found, expected, "{path}");
    }
}

#[test]
fn json_authorization_and_list_assignments_are_detected_without_evidence_leaks() {
    let value = "aB3dE5fG7hI9jK1lM3nO5pQ7";
    assert!(detects(
        "SEC012",
        "headers.json",
        &format!("{{\"Authorization\": \"Bearer {value}\"}}")
    ));
    assert!(detects(
        "SEC009",
        "compose.yml",
        &format!("  - API_KEY={value}")
    ));
}

fn custom(pattern: &str, capture: usize) -> Config {
    Config {
        rules: vec![CustomRule {
            id: "ORG001".into(),
            title: "Marker".into(),
            remediation: "Review".into(),
            severity: Severity::Low,
            category: Category::Privacy,
            pattern: pattern.into(),
            capture,
            min_entropy: None,
            path: None,
        }],
        ..Config::default()
    }
}

#[test]
fn empty_optional_captures_do_not_create_findings_or_escape_work_limits() {
    let rules = RulePack::compile(&custom(r"x(a*)", 1)).unwrap();
    let mut findings = 0;
    assert!(rules.inspect_content("file.txt", "x", |_| {
        findings += 1;
        true
    }));
    assert_eq!(findings, 0);
    assert!(
        !rules.inspect_content("file.txt", &"x".repeat(32_769), |_| {
            findings += 1;
            true
        })
    );
    assert_eq!(findings, 0);
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("file.txt"), "x".repeat(32_769)).unwrap();
    let report = scan(
        &options(root.path()),
        &custom(r"x(a*)", 1),
        &Baseline::empty(),
    )
    .unwrap();
    assert!(!report.complete);
    assert!(report.notices.iter().any(|n| n.code == "candidate_limit"));
}

#[test]
fn library_inputs_are_validated_like_loaded_policy_and_baselines() {
    let root = tempfile::tempdir().unwrap();
    let mut baseline = Baseline::empty();
    baseline.schema_version = 999;
    assert!(scan(&options(root.path()), &Config::default(), &baseline).is_err());
    baseline.schema_version = 1;
    baseline.fingerprints.insert("invalid".into());
    assert!(scan(&options(root.path()), &Config::default(), &baseline).is_err());
    let mut config = Config {
        schema_version: 999,
        ..Config::default()
    };
    assert!(RulePack::compile(&config).is_err());
    config.schema_version = 1;
    config.exclude.push("a".repeat(4097));
    assert!(RulePack::compile(&config).is_err());
}

#[test]
fn explicit_policy_bom_is_accepted_and_diagnostics_do_not_echo_source() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("policy.toml");
    fs::write(&path, "\u{feff}schema_version = 1\n").unwrap();
    assert!(Config::load(&path).is_ok());
    fs::write(&path, "never-echo-this-secret = [invalid").unwrap();
    assert!(!format!("{:#}", Config::load(&path).unwrap_err()).contains("never-echo-this-secret"));
}

#[cfg(unix)]
#[test]
fn explicit_inputs_reject_fifos_and_links_without_reading_targets() {
    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("pipe");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert!(Config::load(&fifo).is_err());
    assert!(Baseline::load(&fifo).is_err());
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&fifo, &link).unwrap();
    assert!(Config::load(&link).is_err());
    assert!(Baseline::load(&link).is_err());
}

#[test]
fn correlation_samples_retain_both_supporting_signals() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join(".github/workflows")).unwrap();
    fs::write(
        root.path().join(".github/workflows/build.yml"),
        "permissions: write-all",
    )
    .unwrap();
    fs::write(root.path().join("Dockerfile"), "COPY . /app").unwrap();
    for index in 0..40 {
        fs::write(
            root.path().join(format!("{index}.txt")),
            format!("ghp_{}", "A".repeat(36)),
        )
        .unwrap();
    }
    let report = scan_default(root.path());
    for (id, supporting_rule) in [("EXP001", "CI001"), ("EXP002", "RUN001")] {
        let correlation = report.correlations.iter().find(|c| c.id == id).unwrap();
        assert!(correlation.members.len() <= 16);
        for rule in ["SEC002", supporting_rule] {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|f| f.rule_id == rule && correlation.members.contains(&f.fingerprint))
            );
        }
    }
}

#[test]
fn every_report_format_exposes_notice_truncation_and_escapes_hypotheses() {
    let root = tempfile::tempdir().unwrap();
    let mut report = scan_default(root.path());
    report.complete = false;
    report.statistics.coverage_notices = 513;
    report.notices.push(prismwarden::model::Notice {
        path: ".".into(),
        code: "read_error".into(),
    });
    report.correlations.push(prismwarden::model::Correlation {
        id: "EXP001".into(),
        title: "<script>\x1b\u{202e}".into(),
        explanation: "[link](url)".into(),
        members: vec![],
    });
    for format in [Format::Text, Format::Markdown] {
        let text = String::from_utf8(output::render(&report, format).unwrap()).unwrap();
        assert!(text.contains("total: 513"));
        assert!(!text.contains('\x1b'));
        assert!(!text.contains('\u{202e}'));
        if matches!(format, Format::Markdown) {
            assert!(!text.contains("<script>"));
        }
    }
    let sarif = output::sarif(&report);
    assert_eq!(
        sarif["runs"][0]["properties"]["statistics"]["coverage_notices"],
        513
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}
