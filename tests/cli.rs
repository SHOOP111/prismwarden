use std::fs;
use std::process::{Command, Output};
use tempfile::TempDir;

fn cli(directory: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_prismwarden"))
        .current_dir(directory.path())
        .args(args)
        .output()
        .unwrap()
}

fn seed(directory: &TempDir) {
    let marker = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
    fs::write(directory.path().join("key.txt"), marker).unwrap();
}

#[test]
fn help_and_rules_are_available_without_scanning() {
    let dir = TempDir::new().unwrap();
    assert!(cli(&dir, &["--help"]).status.success());
    let output = cli(&dir, &["rules", "--json"]);
    assert!(output.status.success());
    let rules: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rules.as_array().unwrap().len(), 29);
}

#[test]
fn cli_thresholds_and_machine_output() {
    let dir = TempDir::new().unwrap();
    seed(&dir);
    let output = cli(&dir, &["scan", ".", "--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(serde_json::from_slice::<serde_json::Value>(&output.stdout).is_ok());
    assert!(output.stderr.is_empty());
    assert_eq!(
        cli(&dir, &["scan", ".", "--fail-on", "none"]).status.code(),
        Some(0)
    );
}

#[test]
fn baseline_roundtrip_and_no_accidental_overwrite() {
    let dir = TempDir::new().unwrap();
    seed(&dir);
    assert_eq!(cli(&dir, &["baseline", "create"]).status.code(), Some(0));
    assert_eq!(cli(&dir, &["baseline", "create"]).status.code(), Some(2));
    assert_eq!(
        cli(&dir, &["scan", "--baseline", ".prismwarden/baseline.json"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        cli(&dir, &["baseline", "create", "--force"]).status.code(),
        Some(0)
    );
}

#[test]
fn incomplete_scans_never_create_a_baseline() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("binary"), [0, 1, 2]).unwrap();
    assert_eq!(cli(&dir, &["scan"]).status.code(), Some(3));
    assert_eq!(
        cli(&dir, &["scan", "--allow-incomplete"]).status.code(),
        Some(0)
    );
    assert_eq!(cli(&dir, &["baseline", "create"]).status.code(), Some(3));
    assert!(!dir.path().join(".prismwarden/baseline.json").exists());
}

#[test]
fn invalid_root_flags_and_policy_are_operational_errors() {
    let dir = TempDir::new().unwrap();
    assert_eq!(cli(&dir, &["scan", "not-present"]).status.code(), Some(2));
    assert_eq!(
        cli(&dir, &["scan", "--threads", "0"]).status.code(),
        Some(2)
    );
    assert_eq!(
        cli(&dir, &["scan", "--max-findings", "0"]).status.code(),
        Some(2)
    );
    assert_eq!(
        cli(&dir, &["scan", "--invalid-flag"]).status.code(),
        Some(2)
    );
    fs::write(dir.path().join("policy.toml"), "unknown = true").unwrap();
    assert_eq!(
        cli(&dir, &["scan", "--config", "policy.toml"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn scan_does_not_auto_load_a_policy_from_the_target() {
    let dir = TempDir::new().unwrap();
    seed(&dir);
    fs::write(
        dir.path().join("prismwarden.toml"),
        "disable_rules = [\"SEC001\"]",
    )
    .unwrap();
    assert_eq!(cli(&dir, &["scan"]).status.code(), Some(1));
    assert_eq!(
        cli(&dir, &["scan", "--config", "prismwarden.toml"])
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn no_ignore_is_an_explicit_cli_scope_change() {
    let dir = TempDir::new().unwrap();
    seed(&dir);
    fs::write(dir.path().join(".prismwardenignore"), "key.txt\n").unwrap();
    assert_eq!(cli(&dir, &["scan"]).status.code(), Some(0));
    assert_eq!(
        cli(&dir, &["scan", "--include-ignored"]).status.code(),
        Some(0)
    );
    let output = cli(&dir, &["scan", "--no-ignore", "--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["scope"]["no_ignore"], true);
    assert_eq!(report["scope"]["include_gitignored"], true);
}

#[test]
fn output_is_atomic_and_stdout_stays_empty() {
    let dir = TempDir::new().unwrap();
    seed(&dir);
    let output = cli(
        &dir,
        &[
            "scan",
            "--format",
            "sarif",
            "--output",
            ".prismwarden/report.sarif",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let bytes = fs::read(dir.path().join(".prismwarden/report.sarif")).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report["version"], "2.1.0");
}
