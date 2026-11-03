use prismwarden::baseline::Baseline;
use prismwarden::config::Config;
use prismwarden::rules::RulePack;
use prismwarden::{ScanOptions, Severity, scan};
use proptest::prelude::*;
use std::sync::LazyLock;

static RULES: LazyLock<RulePack> = LazyLock::new(|| RulePack::compile(&Config::default()).unwrap());

#[test]
fn retention_cannot_hide_an_observed_high_severity_finding() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("a.txt"),
        ["/home/", "synthetic/project"].concat(),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("z.txt"),
        format!("ghp_{}", "Z".repeat(36)),
    )
    .unwrap();
    let options = ScanOptions {
        root: directory.path().into(),
        max_findings: 1,
        ..ScanOptions::default()
    };
    let report = scan(&options, &Config::default(), &Baseline::empty()).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].severity, Severity::Low);
    assert_eq!(report.highest_severity, Some(Severity::High));
    assert_eq!(report.severity_counts["high"], 1);
    assert_eq!(report.exit_code(Some(Severity::High), true), 1);
    assert_eq!(report.exit_code(Some(Severity::High), false), 3);
    assert_eq!(report.scope.max_findings, 1);
}

#[test]
fn dense_single_line_coordinates_do_not_drift() {
    let token = format!("ghp_{}", "A".repeat(36));
    let text = format!("λ{token} ").repeat(1000);
    // A Unicode letter directly preceding a token prevents the word boundary.
    let mut blocked = 0;
    RULES.inspect_content("a.txt", &text, |_| {
        blocked += 1;
        true
    });
    assert_eq!(blocked, 0);
    let text = format!("λ {token} ").repeat(1000);
    let mut columns = Vec::new();
    RULES.inspect_content("a.txt", &text, |finding| {
        columns.push(finding.column);
        true
    });
    assert_eq!(columns.len(), 1000);
    for (index, column) in columns.iter().enumerate() {
        assert_eq!(*column, 3 + index * 43);
    }
}

proptest! {
    #[test]
    fn unicode_coordinates_agree_with_a_reference(prefix in proptest::collection::vec(any::<char>(), 0..200)) {
        let prefix: String = prefix.into_iter().collect();
        let token = format!("ghp_{}", "A".repeat(36));
        let text = format!("{prefix}\n{token}\n{prefix} {token}");
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let mut actual = Vec::new();
        RULES.inspect_content("a.txt", text, |finding| {
            if finding.rule_id == "SEC002" { actual.push((finding.line, finding.column)); }
            true
        });
        let expected: Vec<_> = text.match_indices(&token).map(|(offset, _)| {
            let before = text[..offset].replace("\r\n", "\n").replace('\r', "\n");
            let line = before.bytes().filter(|b| *b == b'\n').count() + 1;
            let column = before.rsplit('\n').next().unwrap().chars().count() + 1;
            (line, column)
        }).collect();
        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn arbitrary_utf8_never_panics_and_locations_are_positive(text in ".{0,2048}") {
        RULES.inspect_content("untrusted.txt", &text, |finding| {
            assert!(finding.line > 0 && finding.column > 0);
            assert_eq!(finding.fingerprint.len(), 64);
            true
        });
    }
}
