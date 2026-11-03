//! Offline auditing engine. No networking, credential validation, or target execution.
//!
//! Policy and baselines are explicit inputs; a report is complete only within its
//! declared scope. Coverage failures take precedence over severity thresholds.
//!
//! # Example
//!
//! This example creates a synthetic snapshot, scans it, and applies the same
//! fail-closed exit policy as the CLI. The scanner itself never changes the input.
//!
//! ```
//! use prismwarden::baseline::Baseline;
//! use prismwarden::config::Config;
//! use prismwarden::{ScanOptions, Severity, scan};
//!
//! # fn main() -> anyhow::Result<()> {
//! let snapshot = tempfile::tempdir()?;
//! std::fs::write(snapshot.path().join("public.txt"), "ordinary public input")?;
//! let options = ScanOptions {
//!     root: snapshot.path().into(),
//!     threads: 1,
//!     ..ScanOptions::default()
//! };
//! let report = scan(&options, &Config::default(), &Baseline::empty())?;
//! assert!(report.complete);
//! assert_eq!(report.statistics.files_scanned, 1);
//! assert_eq!(report.exit_code(Some(Severity::High), false), 0);
//! # Ok(())
//! # }
//! ```
pub mod baseline;
pub mod config;
pub mod correlate;
pub mod engine;
mod file_io;
pub mod model;
pub mod output;
pub mod rules;

pub use engine::{ScanOptions, scan};
pub use model::{Finding, Report, Severity};
