//! Offline auditing engine. No networking, credential validation, or target execution.
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
