use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use prismwarden::baseline::Baseline;
use prismwarden::config::Config;
use prismwarden::output::{self, Format};
use prismwarden::rules::RulePack;
use prismwarden::{ScanOptions, Severity, scan};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "prismwarden", version, about = "Offline OPSEC auditing. No telemetry, network calls, or secret values in reports.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a source tree and enforce a severity threshold.
    Scan {
        #[command(flatten)]
        input: Input,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
        /// Write atomically to this file instead of stdout. Prefer .prismwarden/.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Suppress previously reviewed finding fingerprints.
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "high")]
        fail_on: Threshold,
        /// Permit a policy pass despite unreadable, binary, oversized, or truncated input.
        #[arg(long)]
        allow_incomplete: bool,
    },
    /// Create a fingerprint-only baseline from a complete scan. Review before committing.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// List active detection rules; does not read the target tree.
    Rules {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum BaselineCommand {
    Create {
        #[command(flatten)]
        input: Input,
        #[arg(short, long, default_value = ".prismwarden/baseline.json")]
        output: PathBuf,
        /// Replace an existing baseline after review.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args)]
struct Input {
    /// Directory to inspect. The absolute path is not included in reports.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Explicit trusted policy. Never auto-loaded from the scan tree.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Include gitignored files; .prismwardenignore and hard-pruned directories still apply.
    #[arg(long)]
    include_ignored: bool,
    #[arg(long)]
    threads: Option<usize>,
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    max_file_bytes: u64,
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    max_total_bytes: u64,
    #[arg(long, default_value_t = 50_000)]
    max_files: usize,
    #[arg(long, default_value_t = 10_000)]
    max_findings: usize,
}

#[derive(Clone, Copy, ValueEnum)]
enum Threshold { Low, Medium, High, Critical, None }

impl Threshold {
    fn severity(self) -> Option<Severity> {
        match self {
            Self::Low => Some(Severity::Low), Self::Medium => Some(Severity::Medium),
            Self::High => Some(Severity::High), Self::Critical => Some(Severity::Critical), Self::None => None,
        }
    }
}

impl Input {
    fn options(&self) -> ScanOptions {
        ScanOptions {
            root: self.path.clone(), include_ignored: self.include_ignored,
            threads: self.threads.unwrap_or_else(|| ScanOptions::default().threads),
            max_file_bytes: self.max_file_bytes, max_total_bytes: self.max_total_bytes,
            max_files: self.max_files, max_findings: self.max_findings,
        }
    }

    fn policy(&self) -> Result<Config> { load_config(self.config.as_ref()) }
}

fn load_config(path: Option<&PathBuf>) -> Result<Config> {
    path.map_or_else(|| Ok(Config::default()), |p| Config::load(p))
}

fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Command::Scan { input, format, output, baseline, fail_on, allow_incomplete } => {
            let baseline = baseline.map_or_else(|| Ok(Baseline::empty()), |p| Baseline::load(&p))?;
            let report = scan(&input.options(), &input.policy()?, &baseline)?;
            let bytes = output::render(&report, format)?;
            if let Some(path) = output { output::write_atomic(&path, &bytes, true)?; }
            else { stdout(&bytes)?; }
            Ok(report.exit_code(fail_on.severity(), allow_incomplete))
        }
        Command::Baseline { command: BaselineCommand::Create { input, output, force } } => {
            let report = scan(&input.options(), &input.policy()?, &Baseline::empty())?;
            if !report.complete {
                stdout(&output::render(&report, Format::Text)?)?;
                eprintln!("Baseline not written: scan coverage is incomplete. Review exclusions or increase the budgets.");
                return Ok(3);
            }
            let baseline = Baseline::from_report(&report)?;
            output::write_atomic(&output, &serde_json::to_vec_pretty(&baseline)?, force)?;
            eprintln!("Baseline written with {} fingerprints. Review every suppression before committing.", baseline.fingerprints.len());
            Ok(0)
        }
        Command::Rules { config, json } => {
            let config = load_config(config.as_ref())?;
            let rules = RulePack::compile(&config)?;
            prismwarden::config::Policy::compile(&config, rules.known_ids())?;
            if json { stdout(&serde_json::to_vec_pretty(&rules.catalog())?)?; }
            else {
                for rule in rules.catalog() {
                    stdout(format!("{}\t{}\t{}\n", output::safe_text(&rule.id), rule.severity, output::safe_text(&rule.title)).as_bytes())?;
                }
            }
            Ok(0)
        }
    }
}

fn stdout(bytes: &[u8]) -> Result<()> {
    match std::io::stdout().lock().write_all(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("prismwarden: {}", output::safe_text(&format!("{error:#}")));
            ExitCode::from(2)
        }
    }
}
