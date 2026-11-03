//! Repeated synthetic end-to-end measurements. Run only on GitHub Actions.
use prismwarden::baseline::Baseline;
use prismwarden::config::Config;
use prismwarden::{ScanOptions, scan};
use serde::Serialize;
use std::time::Instant;

const THREADS: [usize; 3] = [1, 2, 4];
const REPEATS: usize = 5;

#[derive(Serialize)]
struct Measurement {
    corpus: String,
    threads: usize,
    files: u64,
    bytes: u64,
    findings: usize,
    samples_seconds: Vec<f64>,
    median_seconds: f64,
    min_seconds: f64,
    max_seconds: f64,
    median_mib_per_second: f64,
}

fn corpus(name: &str) -> anyhow::Result<(tempfile::TempDir, usize)> {
    let root = tempfile::tempdir()?;
    let token = format!("\nghp_{}\n", "A".repeat(36));
    let ordinary = "const PUBLIC_SETTING: &str = \"ordinary synthetic input\";\n";
    let (files, expected) = match name {
        "large_low_hit" => (384, 24),
        "tiny_files" => (1024, 64),
        "dense_findings" => (64, 2048),
        "long_unicode_lines" => (96, 96),
        "entropy_rejects" => (64, 0),
        _ => anyhow::bail!("unknown synthetic corpus"),
    };
    for index in 0..files {
        let contents = match name {
            "large_low_hit" => ordinary.repeat(2400) + if index % 16 == 0 { &token } else { "" },
            "tiny_files" => ordinary.to_owned() + if index % 16 == 0 { &token } else { "" },
            "dense_findings" => token.repeat(32),
            "long_unicode_lines" => "λ ordinary ".repeat(4096) + &token,
            "entropy_rejects" => format!("{} = {}\n", "API_KEY", "a".repeat(32)).repeat(256),
            _ => unreachable!(),
        };
        std::fs::write(
            root.path().join(format!("fixture-{index:04}.txt")),
            contents,
        )?;
    }
    Ok((root, expected))
}

fn main() -> anyhow::Result<()> {
    let mut measurements = Vec::new();
    for name in [
        "large_low_hit",
        "tiny_files",
        "dense_findings",
        "long_unicode_lines",
        "entropy_rejects",
    ] {
        let (root, expected) = corpus(name)?;
        let mut reference = None;
        let start = measurements.len();
        for threads in THREADS {
            measurements.push(Measurement {
                corpus: name.into(),
                threads,
                files: 0,
                bytes: 0,
                findings: expected,
                samples_seconds: Vec::with_capacity(REPEATS),
                median_seconds: 0.0,
                min_seconds: 0.0,
                max_seconds: 0.0,
                median_mib_per_second: 0.0,
            });
        }
        // One warm-up per worker count; rotate order on each measured round.
        for round in 0..=REPEATS {
            for step in 0..THREADS.len() {
                let slot = (step + round) % THREADS.len();
                let measurement = &mut measurements[start + slot];
                let options = ScanOptions {
                    root: root.path().into(),
                    threads: measurement.threads,
                    ..ScanOptions::default()
                };
                let started = Instant::now();
                let report = scan(&options, &Config::default(), &Baseline::empty())?;
                let seconds = started.elapsed().as_secs_f64();
                anyhow::ensure!(
                    report.complete && report.findings.len() == expected,
                    "synthetic coverage/detection regression in {name}"
                );
                // Serialization/digesting is outside the timed region. Compare
                // the entire report across rounds and worker counts, not counts alone.
                let digest = blake3::hash(&serde_json::to_vec(&report)?);
                if let Some(reference) = reference {
                    anyhow::ensure!(
                        digest == reference,
                        "nondeterministic synthetic report in {name}"
                    );
                } else {
                    reference = Some(digest);
                }
                measurement.files = report.statistics.files_scanned;
                measurement.bytes = report.statistics.bytes_read;
                if round != 0 {
                    measurement.samples_seconds.push(seconds);
                }
            }
        }
        for measurement in &mut measurements[start..] {
            let mut sorted = measurement.samples_seconds.clone();
            sorted.sort_by(f64::total_cmp);
            measurement.min_seconds = sorted[0];
            measurement.max_seconds = sorted[REPEATS - 1];
            measurement.median_seconds = sorted[REPEATS / 2];
            measurement.median_mib_per_second =
                measurement.bytes as f64 / 1_048_576.0 / measurement.median_seconds;
        }
    }
    println!("{}", serde_json::to_string_pretty(&measurements)?);
    Ok(())
}
