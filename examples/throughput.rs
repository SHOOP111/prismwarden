//! Synthetic end-to-end measurement, intended to run only in GitHub Actions.
use prismwarden::baseline::Baseline;
use prismwarden::config::Config;
use prismwarden::{ScanOptions, scan};
use serde::Serialize;
use std::time::Instant;

#[derive(Serialize)]
struct Measurement {
    threads: usize,
    files: u64,
    bytes: u64,
    seconds: f64,
    mib_per_second: f64,
    findings: usize,
}

fn main() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let ordinary = "const PUBLIC_SETTING: &str = \"ordinary synthetic input\";\n".repeat(2400);
    for index in 0..384 {
        let mut contents = ordinary.clone();
        if index % 16 == 0 {
            contents.push_str(&format!("\n{}{}\n", "ghp_", "A".repeat(36)));
        }
        std::fs::write(root.path().join(format!("fixture-{index:04}.txt")), contents)?;
    }
    let mut measurements = Vec::new();
    for threads in [1, 2, 4] {
        let options = ScanOptions { root: root.path().into(), threads, ..ScanOptions::default() };
        let started = Instant::now();
        let report = scan(&options, &Config::default(), &Baseline::empty())?;
        let seconds = started.elapsed().as_secs_f64();
        anyhow::ensure!(report.complete && report.findings.len() == 24, "synthetic corpus coverage/detection regression");
        measurements.push(Measurement {
            threads,
            files: report.statistics.files_scanned,
            bytes: report.statistics.bytes_read,
            seconds,
            mib_per_second: report.statistics.bytes_read as f64 / 1_048_576.0 / seconds,
            findings: report.findings.len(),
        });
    }
    println!("{}", serde_json::to_string_pretty(&measurements)?);
    Ok(())
}
