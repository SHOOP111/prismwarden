use prismwarden::baseline::Baseline;
use prismwarden::config::{AllowEntry, Config, CustomRule};
use prismwarden::model::{Category, Severity, fingerprint};
use prismwarden::output::{self, Format};
use prismwarden::rules::RulePack;
use prismwarden::{Report, ScanOptions, scan};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;
use tempfile::TempDir;

static RULES: LazyLock<RulePack> = LazyLock::new(|| RulePack::compile(&Config::default()).unwrap());

fn token() -> String {
    ["ghp_", "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"].concat()
}
fn key() -> String {
    ["-----BEGIN ", "OPENSSH PRIVATE KEY-----"].concat()
}

fn put(root: &Path, name: &str, contents: impl AsRef<[u8]>) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn run(root: &Path) -> Report {
    scan(
        &ScanOptions {
            root: root.into(),
            threads: 2,
            ..ScanOptions::default()
        },
        &Config::default(),
        &Baseline::empty(),
    )
    .unwrap()
}

fn detect(path: &str, value: &str) -> Vec<prismwarden::Finding> {
    let mut findings = Vec::new();
    assert!(RULES.inspect_content(path, value, |f| {
        findings.push(f);
        true
    }));
    findings
}

#[test]
fn every_content_detector_has_a_positive_case() {
    let cases = vec![
        ("SEC001", "key.txt", key()),
        ("SEC002", "token.txt", token()),
        ("SEC003", "cloud.txt", format!("AKIA{}", "A1B2C3D4E5F6G7H8")),
        ("SEC004", "chat.txt", format!("xoxb-{}", "Ab12".repeat(12))),
        (
            "SEC005",
            "payment.txt",
            format!("sk_live_{}", "Ab12".repeat(8)),
        ),
        ("SEC006", "map.txt", format!("AIza{}", "A".repeat(35))),
        (
            "SEC007",
            "jwt.txt",
            format!(
                "eyJ{}.{}.{}",
                "a".repeat(12),
                "b".repeat(12),
                "c".repeat(12)
            ),
        ),
        (
            "SEC008",
            "database.txt",
            format!("postgres://user:{}@localhost/db", "never-a-real-credential"),
        ),
        (
            "SEC009",
            "settings.txt",
            format!("API_KEY = \"{}\"", "aB3dE5fG7hI9jK1lM3nO5pQ7"),
        ),
        (
            "SEC010",
            "upload.txt",
            format!("pypi-{}", "Ab12".repeat(20)),
        ),
        ("SEC011", "npm.txt", format!("npm_{}", "Ab12".repeat(9))),
        (
            "SEC012",
            "headers.txt",
            format!("Authorization: Bearer {}", "aB3dE5fG7hI9jK1lM3nO5pQ7"),
        ),
        (
            "CI001",
            ".github/workflows/a.yml",
            "permissions: write-all".into(),
        ),
        (
            "CI002",
            ".github/workflows/a.yml",
            "  - uses: owner/action@v1".into(),
        ),
        (
            "CI003",
            ".github/workflows/a.yml",
            "on: [pull_request_target]".into(),
        ),
        (
            "CI004",
            ".github/workflows/a.yml",
            "    persist-credentials: true".into(),
        ),
        (
            "CI005",
            ".github/workflows/a.yml",
            "run: echo ${{ github.event.issue.title }}".into(),
        ),
        ("RUN001", "Dockerfile", "COPY . /app".into()),
        ("RUN002", "compose.yml", "    privileged: true".into()),
        ("RUN003", "server.toml", "host = \"0.0.0.0\"".into()),
        ("RUN004", "client.js", "tls_verify: false".into()),
        ("RUN005", "server.toml", "DEBUG = true".into()),
        ("RUN006", "sshd_config", "PermitRootLogin yes".into()),
        (
            "PRV001",
            "log.txt",
            ["/home/", "fictional-user/project"].concat(),
        ),
    ];
    assert_eq!(RULES.catalog().len(), cases.len() + 5);
    for (id, path, value) in cases {
        assert!(
            detect(path, &value).iter().any(|f| f.rule_id == id),
            "missing detector: {id}"
        );
    }
}

#[test]
fn every_artifact_detector_has_a_positive_case() {
    for (id, path, mode) in [
        ("ART001", ".env.production", None),
        ("ART002", "terraform.tfstate", None),
        ("ART003", ".DS_Store", None),
        ("ART004", "id_ed25519", None),
        ("PRV002", ".env", Some(0o644)),
    ] {
        let mut ids = Vec::new();
        RULES.inspect_path(path, mode, |f| {
            ids.push(f.rule_id);
            true
        });
        assert!(ids.iter().any(|found| found == id));
    }
}

#[test]
fn detects_hidden_files_without_echoing_evidence() {
    let dir = TempDir::new().unwrap();
    let secret = token();
    put(dir.path(), ".hidden", format!("token: {secret}\n"));
    let report = run(dir.path());
    assert!(report.complete);
    assert!(report.findings.iter().any(|f| f.rule_id == "SEC002"));
    for format in [Format::Text, Format::Json, Format::Sarif, Format::Markdown] {
        let rendered = String::from_utf8(output::render(&report, format).unwrap()).unwrap();
        assert!(!rendered.contains(&secret));
        assert!(!rendered.contains(dir.path().to_str().unwrap()));
    }
}

#[test]
fn baseline_survives_line_shifts_but_not_rotation() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "secret.txt", token());
    let baseline = Baseline::from_report(&run(dir.path())).unwrap();
    put(dir.path(), "secret.txt", format!("\n\n{}", token()));
    let options = ScanOptions {
        root: dir.path().into(),
        ..ScanOptions::default()
    };
    let report = scan(&options, &Config::default(), &baseline).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.statistics.baseline_suppressed, 1);
    put(dir.path(), "secret.txt", format!("ghp_{}", "Z".repeat(36)));
    assert_eq!(
        scan(&options, &Config::default(), &baseline)
            .unwrap()
            .findings
            .len(),
        1
    );
}

#[test]
fn fingerprint_is_domain_separated() {
    assert_ne!(fingerprint("AB", "C", b"D"), fingerprint("A", "BC", b"D"));
    assert_ne!(fingerprint("A", "B", b"C"), fingerprint("A", "C", b"B"));
}

#[test]
fn deterministic_parallel_and_truncated_reports() {
    let dir = TempDir::new().unwrap();
    for index in 0..30 {
        put(
            dir.path(),
            &format!("{index:02}.txt"),
            format!("{}\n{}", token(), key()),
        );
    }
    for limit in [3, 100] {
        let mut options = ScanOptions {
            root: dir.path().into(),
            threads: 1,
            max_findings: limit,
            ..ScanOptions::default()
        };
        let first = scan(&options, &Config::default(), &Baseline::empty()).unwrap();
        options.threads = 4;
        let second = scan(&options, &Config::default(), &Baseline::empty()).unwrap();
        assert_eq!(
            serde_json::to_value(first).unwrap(),
            serde_json::to_value(second).unwrap()
        );
    }
}

#[test]
fn severity_policy_baseline_and_exit_codes() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "key.txt", key());
    let report = run(dir.path());
    assert_eq!(report.exit_code(Some(Severity::High), false), 1);
    assert_eq!(report.exit_code(None, false), 0);
    let mut config = Config::default();
    config.severity.insert("SEC001".into(), Severity::Low);
    let options = ScanOptions {
        root: dir.path().into(),
        ..ScanOptions::default()
    };
    let report = scan(&options, &config, &Baseline::empty()).unwrap();
    assert_eq!(report.exit_code(Some(Severity::High), false), 0);
    config.disable_rules.insert("SEC001".into());
    assert!(
        scan(&options, &config, &Baseline::empty())
            .unwrap()
            .findings
            .is_empty()
    );
}

#[test]
fn allowlist_is_rule_and_path_scoped_and_requires_reason() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "fixture.txt", token());
    put(dir.path(), "real.txt", token());
    let mut config = Config::default();
    config.allow.push(AllowEntry {
        rule: "SEC002".into(),
        path: "fixture.txt".into(),
        reason: "synthetic test data".into(),
    });
    let options = ScanOptions {
        root: dir.path().into(),
        ..ScanOptions::default()
    };
    let report = scan(&options, &config, &Baseline::empty()).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].path, "real.txt");
    assert_eq!(report.statistics.allowlist_suppressed, 1);
    config.allow[0].reason.clear();
    assert!(scan(&options, &config, &Baseline::empty()).is_err());
}

#[test]
fn gitignore_custom_ignore_and_hard_pruning() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), ".gitignore", "ignored.txt\n");
    put(dir.path(), ".prismwardenignore", "custom.txt\n");
    for name in [
        "ignored.txt",
        "custom.txt",
        "target/generated.txt",
        ".git/data.txt",
        ".prismwarden/old.txt",
    ] {
        put(dir.path(), name, token());
    }
    assert!(run(dir.path()).findings.is_empty());
    let options = ScanOptions {
        root: dir.path().into(),
        include_ignored: true,
        ..ScanOptions::default()
    };
    let report = scan(&options, &Config::default(), &Baseline::empty()).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].path, "ignored.txt");
}

#[test]
fn binary_and_invalid_utf8_are_explicit_coverage_gaps() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "binary.bin", b"abc\0def");
    put(dir.path(), "invalid.txt", [0xff, 0xfe]);
    let report = run(dir.path());
    assert!(!report.complete);
    assert_eq!(report.statistics.binary_files, 2);
    assert_eq!(report.exit_code(None, false), 3);
    assert_eq!(report.exit_code(None, true), 0);
    assert!(Baseline::from_report(&report).is_err());
}

#[test]
fn explicit_exclusions_define_the_scan_scope() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "data.bin", [0, 1, 2]);
    let config = Config {
        exclude: vec!["*.bin".into()],
        ..Config::default()
    };
    let options = ScanOptions {
        root: dir.path().into(),
        ..ScanOptions::default()
    };
    let report = scan(&options, &config, &Baseline::empty()).unwrap();
    assert!(report.complete);
    assert_eq!(report.statistics.excluded_by_policy, 1);
}

#[test]
fn file_and_total_byte_budgets_fail_closed() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "a.txt", "hello");
    put(dir.path(), "b.txt", "world");
    let mut options = ScanOptions {
        root: dir.path().into(),
        max_file_bytes: 4,
        ..ScanOptions::default()
    };
    let report = scan(&options, &Config::default(), &Baseline::empty()).unwrap();
    assert!(report.notices.iter().all(|n| n.code == "oversized_file"));
    options.max_file_bytes = 5;
    options.max_total_bytes = 5;
    let report = scan(&options, &Config::default(), &Baseline::empty()).unwrap();
    assert_eq!(report.statistics.bytes_read, 5);
    assert!(report.notices.iter().any(|n| n.code == "byte_budget"));
    options.max_total_bytes = 10;
    options.max_files = 1;
    assert!(
        scan(&options, &Config::default(), &Baseline::empty())
            .unwrap()
            .notices
            .iter()
            .any(|n| n.code == "file_limit")
    );
}

#[test]
fn candidate_and_finding_caps_are_visible() {
    let dir = TempDir::new().unwrap();
    put(
        dir.path(),
        "many.txt",
        format!("{}\n", token()).repeat(2100),
    );
    let options = ScanOptions {
        root: dir.path().into(),
        max_findings: 2,
        ..ScanOptions::default()
    };
    let report = scan(&options, &Config::default(), &Baseline::empty()).unwrap();
    assert_eq!(report.findings.len(), 2);
    assert!(report.notices.iter().any(|n| n.code == "candidate_limit"));
    assert!(report.notices.iter().any(|n| n.code == "finding_limit"));
    assert!(!report.complete);
}

#[test]
fn line_and_unicode_columns_match_sarif() {
    let findings = detect("source.txt", &format!("before\r\nλ {}\r\n", token()));
    let finding = findings.iter().find(|f| f.rule_id == "SEC002").unwrap();
    assert_eq!((finding.line, finding.column), (2, 3));
}

#[test]
fn utf8_bom_is_supported() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "config.toml", "\u{feff}DEBUG = true");
    assert!(
        run(dir.path())
            .findings
            .iter()
            .any(|f| f.rule_id == "RUN005")
    );
}

#[test]
fn negative_context_and_placeholder_cases() {
    assert!(
        detect(
            "README.md",
            "permissions: write-all\nCOPY . /app\nDEBUG = true"
        )
        .is_empty()
    );
    assert!(detect("config.txt", "API_KEY = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_empty());
    assert!(detect("db.txt", "postgres://user:changeme@localhost/db").is_empty());
    let pinned = format!("- uses: owner/action@{}", "a".repeat(40));
    assert!(detect(".github/workflows/build.yml", &pinned).is_empty());
    let mut findings = Vec::new();
    RULES.inspect_path(".env.example", Some(0o644), |f| {
        findings.push(f);
        true
    });
    assert!(findings.is_empty());
}

#[test]
fn correlations_are_contextual_and_reference_real_findings() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "secrets.txt", token());
    put(
        dir.path(),
        ".github/workflows/build.yml",
        "permissions: write-all",
    );
    put(dir.path(), "Dockerfile", "COPY . /app");
    put(
        dir.path(),
        "server.toml",
        "host = \"0.0.0.0\"\nDEBUG = true",
    );
    let report = run(dir.path());
    assert_eq!(report.correlations.len(), 3);
    for correlation in &report.correlations {
        assert!(
            correlation
                .members
                .iter()
                .all(|id| report.findings.iter().any(|f| &f.fingerprint == id))
        );
    }
}

#[test]
fn unrelated_services_do_not_form_a_debug_exposure() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "a.toml", "host = \"0.0.0.0\"");
    put(dir.path(), "b.toml", "DEBUG = true");
    assert!(run(dir.path()).correlations.is_empty());
}

#[test]
fn custom_rules_are_bounded_validated_and_path_scoped() {
    let custom = CustomRule {
        id: "ORG001".into(),
        title: "Internal marker".into(),
        remediation: "Review distribution".into(),
        severity: Severity::Medium,
        category: Category::Privacy,
        pattern: r"INTERNAL-([A-Z]{6})".into(),
        capture: 1,
        min_entropy: None,
        path: Some("*.txt".into()),
    };
    let mut config = Config {
        rules: vec![custom],
        ..Config::default()
    };
    let pack = RulePack::compile(&config).unwrap();
    let mut found = Vec::new();
    pack.inspect_content("a.txt", "INTERNAL-ABCDEF", |f| {
        found.push(f);
        true
    });
    pack.inspect_content("a.rs", "INTERNAL-ABCDEF", |f| {
        found.push(f);
        true
    });
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].column, 10);
    config.rules[0].capture = 9;
    assert!(RulePack::compile(&config).is_err());
    config.rules[0].capture = 0;
    config.rules[0].pattern = ".*".into();
    assert!(RulePack::compile(&config).is_err());
    config.rules[0].pattern = "(?=unsupported-lookaround)".into();
    assert!(RulePack::compile(&config).is_err());
}

#[test]
fn unknown_policy_rules_are_errors() {
    let dir = TempDir::new().unwrap();
    let mut config = Config::default();
    config.disable_rules.insert("TYPO001".into());
    let options = ScanOptions {
        root: dir.path().into(),
        ..ScanOptions::default()
    };
    assert!(scan(&options, &config, &Baseline::empty()).is_err());
}

#[test]
fn config_and_baseline_parsers_reject_unknown_fields_and_schemas() {
    let dir = TempDir::new().unwrap();
    let config = dir.path().join("policy.toml");
    fs::write(&config, "schema_version = 2").unwrap();
    assert!(Config::load(&config).is_err());
    fs::write(&config, "exclude_typo = []").unwrap();
    assert!(Config::load(&config).is_err());
    let baseline = dir.path().join("baseline.json");
    fs::write(&baseline, r#"{"schema_version":1,"fingerprints":["bad"]}"#).unwrap();
    assert!(Baseline::load(&baseline).is_err());
    fs::write(&baseline, serde_json::to_vec(&Baseline::empty()).unwrap()).unwrap();
    assert!(Baseline::load(&baseline).is_ok());
}

#[test]
fn sarif_indices_and_schema_fields_are_consistent() {
    let dir = TempDir::new().unwrap();
    put(dir.path(), "a #.txt", format!("{}\n{}", key(), token()));
    let document = output::sarif(&run(dir.path()));
    assert_eq!(document["version"], "2.1.0");
    let run = &document["runs"][0];
    assert_eq!(run["columnKind"], "unicodeCodePoints");
    for result in run["results"].as_array().unwrap() {
        let index = result["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(
            result["ruleId"],
            run["tool"]["driver"]["rules"][index]["id"]
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "a%20%23.txt"
        );
    }
}

#[cfg(unix)]
#[test]
fn never_follows_symlinks_or_reads_fifos() {
    use std::os::unix::fs::symlink;
    use std::process::Command;
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    put(outside.path(), "secret.txt", token());
    symlink(
        outside.path().join("secret.txt"),
        dir.path().join("linked.txt"),
    )
    .unwrap();
    symlink(outside.path(), dir.path().join("linked-directory")).unwrap();
    symlink(dir.path(), dir.path().join("cycle")).unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(dir.path().join("pipe"))
            .status()
            .unwrap()
            .success()
    );
    let report = run(dir.path());
    assert!(report.findings.is_empty());
    assert_eq!(report.statistics.symlinks_skipped, 3);
    assert_eq!(report.statistics.special_files_skipped, 1);
}

// APFS rejects invalid UTF-8 filenames before the scanner can see them.
// Lossless relative-path handling is also unit-tested without filesystem I/O.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_paths_are_reported_not_lossily_collided() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(OsString::from_vec(vec![0xff, b'a'])),
        token(),
    )
    .unwrap();
    let report = run(dir.path());
    assert!(!report.complete);
    assert!(
        report
            .notices
            .iter()
            .any(|n| n.code == "unsupported_path_encoding")
    );
}

#[cfg(unix)]
#[test]
fn refuses_symlink_output_without_touching_target() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new().unwrap();
    put(dir.path(), "original", "preserve");
    symlink(dir.path().join("original"), dir.path().join("report")).unwrap();
    assert!(output::write_atomic(&dir.path().join("report"), b"replace", true).is_err());
    assert_eq!(fs::read(dir.path().join("original")).unwrap(), b"preserve");
}
