use crate::model::{Report, Severity};
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
    Markdown,
}

pub fn render(report: &Report, format: Format) -> Result<Vec<u8>> {
    let mut output = match format {
        Format::Json => serde_json::to_vec_pretty(report)?,
        Format::Sarif => serde_json::to_vec_pretty(&sarif(report))?,
        Format::Text => text(report).into_bytes(),
        Format::Markdown => markdown(report).into_bytes(),
    };
    if !output.ends_with(b"\n") {
        output.push(b'\n');
    }
    Ok(output)
}

pub fn write_atomic(path: &Path, contents: &[u8], overwrite: bool) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "output must be a regular file, not a symlink or directory"
        );
        ensure!(
            overwrite,
            "output already exists; use --force to replace a reviewed baseline"
        );
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).context("cannot create output directory")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("cannot create temporary output")?;
    temporary
        .write_all(contents)
        .context("cannot write report")?;
    temporary
        .as_file()
        .sync_all()
        .context("cannot sync report")?;
    if overwrite {
        temporary
            .persist(path)
            .map_err(|_| anyhow::anyhow!("cannot atomically replace output"))?;
    } else {
        temporary.persist_noclobber(path).map_err(|_| {
            anyhow::anyhow!("cannot publish output without overwriting an existing file")
        })?;
    }
    Ok(())
}

fn text(report: &Report) -> String {
    let mut out = String::new();
    let status = if report.complete {
        "COMPLETE (declared scope)"
    } else {
        "INCOMPLETE"
    };
    writeln!(out, "PRISMWARDEN / offline OPSEC audit / {status}").unwrap();
    writeln!(
        out,
        "{} text files | {} bytes | {} findings | {} baseline-suppressed | {} allowlisted",
        report.statistics.files_scanned,
        report.statistics.bytes_read,
        report.findings.len(),
        report.statistics.baseline_suppressed,
        report.statistics.allowlist_suppressed
    )
    .unwrap();
    for finding in &report.findings {
        writeln!(
            out,
            "\n[{}] {}  {}:{}:{}\n  {}\n  Fix: {}",
            finding.severity,
            safe_text(&finding.rule_id),
            safe_text(&finding.path),
            finding.line,
            finding.column,
            safe_text(&finding.title),
            safe_text(&finding.remediation)
        )
        .unwrap();
    }
    for correlation in &report.correlations {
        writeln!(
            out,
            "\n[review hypothesis] {}: {}\n  {}",
            correlation.id, correlation.title, correlation.explanation
        )
        .unwrap();
    }
    for notice in &report.notices {
        writeln!(
            out,
            "[coverage] {}: {}",
            safe_text(&notice.path),
            safe_text(&notice.code)
        )
        .unwrap();
    }
    if report.statistics.coverage_notices > report.notices.len() as u64 {
        writeln!(
            out,
            "Additional coverage notices omitted; total: {}",
            report.statistics.coverage_notices
        )
        .unwrap();
    }
    writeln!(
        out,
        "\nMatched values are never rendered. Paths and fingerprints may still be sensitive."
    )
    .unwrap();
    out
}

fn markdown(report: &Report) -> String {
    let mut out = format!(
        "# PrismWarden audit\n\nCoverage: **{}**. {} text files, {} findings.\n\n",
        if report.complete {
            "complete within declared scope"
        } else {
            "INCOMPLETE"
        },
        report.statistics.files_scanned,
        report.findings.len()
    );
    out.push_str("| Severity | Rule | Location | Finding | Remediation |\n|---|---|---|---|---|\n");
    for finding in &report.findings {
        writeln!(
            out,
            "| {} | {} | {}:{}:{} | {} | {} |",
            finding.severity,
            markdown_escape(&finding.rule_id),
            markdown_escape(&finding.path),
            finding.line,
            finding.column,
            markdown_escape(&finding.title),
            markdown_escape(&finding.remediation)
        )
        .unwrap();
    }
    if !report.correlations.is_empty() {
        out.push_str("\n## Review hypotheses (not proven exploit paths)\n");
    }
    for correlation in &report.correlations {
        writeln!(
            out,
            "\n### {}: {}\n\n{}",
            correlation.id, correlation.title, correlation.explanation
        )
        .unwrap();
    }
    if !report.notices.is_empty() {
        out.push_str("\n## Coverage notices\n");
    }
    for notice in &report.notices {
        writeln!(
            out,
            "- {}: {}",
            markdown_escape(&notice.path),
            markdown_escape(&notice.code)
        )
        .unwrap();
    }
    out.push_str(
        "\nMatched values are omitted. Review paths and fingerprints before sharing this report.\n",
    );
    out
}

pub fn sarif(report: &Report) -> Value {
    let mut distinct = BTreeMap::new();
    for finding in &report.findings {
        distinct.entry(&finding.rule_id).or_insert(finding);
    }
    let mut indices = BTreeMap::new();
    let rules: Vec<_> = distinct.iter().enumerate().map(|(index, (id, finding))| {
        indices.insert(*id, index);
        json!({
            "id": id,
            "shortDescription": { "text": finding.title },
            "fullDescription": { "text": finding.remediation },
            "help": { "text": finding.remediation },
            "defaultConfiguration": { "level": sarif_level(finding.severity) },
            "properties": { "security-severity": security_score(finding.severity), "tags": ["security", "opsec"] }
        })
    }).collect();
    let results: Vec<_> = report.findings.iter().map(|finding| json!({
        "ruleId": finding.rule_id,
        "ruleIndex": indices[&finding.rule_id],
        "level": sarif_level(finding.severity),
        "message": { "text": format!("{} — {}", finding.title, finding.remediation) },
        "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": uri_path(&finding.path), "uriBaseId": "%SRCROOT%" },
            "region": { "startLine": finding.line, "startColumn": finding.column }
        }}],
        "partialFingerprints": { "prismwarden/v1": finding.fingerprint }
    })).collect();
    let notifications: Vec<_> = report
        .notices
        .iter()
        .map(|notice| {
            json!({
                "level": "warning", "descriptor": { "id": notice.code },
                "message": { "text": format!("{}: {}", safe_text(&notice.path), notice.code) }
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "PrismWarden", "version": report.version,
                "informationUri": "https://github.com/SHOOP111/prismwarden", "rules": rules } },
            "columnKind": "unicodeCodePoints",
            "invocations": [{ "executionSuccessful": report.complete, "toolExecutionNotifications": notifications }],
            "results": results,
            "properties": { "rulepackDigest": report.rulepack_digest, "complete": report.complete }
        }]
    })
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn security_score(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.0",
        Severity::Low => "2.0",
    }
}

/// Prevent control-character and bidi injection into human-readable output.
pub fn safe_text(text: &str) -> String {
    let mut output = String::new();
    for ch in text.chars() {
        if ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            write!(output, "\\u{{{:x}}}", ch as u32).unwrap();
        } else {
            output.push(ch);
        }
    }
    output
}

fn markdown_escape(text: &str) -> String {
    let mut output = String::new();
    for ch in safe_text(text).chars() {
        if ch.is_ascii_punctuation() {
            write!(output, "&#{};", ch as u32).unwrap();
        } else {
            output.push(ch);
        }
    }
    output
}

pub fn uri_path(path: &str) -> String {
    let mut output = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            output.push(byte as char);
        } else {
            write!(output, "%{byte:02X}").unwrap();
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn human_output_escapes_controls() {
        assert_eq!(
            safe_text("a\x1b[31m\n\u{202e}b"),
            "a\\u{1b}[31m\\u{a}\\u{202e}b"
        );
        assert!(!markdown_escape("<script>|[click](url)").contains('<'));
    }
    #[test]
    fn uris_are_relative_and_percent_encoded() {
        assert_eq!(uri_path("src/a b#c%é.rs"), "src/a%20b%23c%25%C3%A9.rs");
    }
    #[test]
    fn atomic_output_and_no_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/report.json");
        write_atomic(&path, b"first", false).unwrap();
        assert!(write_atomic(&path, b"second", false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        write_atomic(&path, b"second", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
