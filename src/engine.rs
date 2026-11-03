use crate::baseline::Baseline;
use crate::config::{Config, Policy};
use crate::correlate;
use crate::file_io::{self, is_link};
use crate::model::{Finding, Notice, Report, SCHEMA_VERSION, ScanScope, Severity, Statistics};
use crate::rules::RulePack;
use anyhow::{Context, Result, ensure};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const NOTICE_LIMIT: usize = 512;
const CANDIDATES_PER_FILE: usize = 2048;
const MAX_DEPTH: usize = 64;
const PRUNED: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    ".venv",
    ".prismwarden",
];

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub root: PathBuf,
    pub include_ignored: bool,
    /// Bypass all target-controlled ignore files; explicit policy/pruning remain.
    pub no_ignore: bool,
    pub threads: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_files: usize,
    pub max_findings: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            include_ignored: false,
            no_ignore: false,
            threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(8)),
            max_file_bytes: 2 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_files: 50_000,
            max_findings: 10_000,
        }
    }
}

struct Work {
    absolute: PathBuf,
    relative: String,
    metadata: Metadata,
    content_notice: Option<&'static str>,
}

struct Accumulator {
    statistics: Statistics,
    severity_counts: BTreeMap<String, u64>,
    highest_severity: Option<Severity>,
    findings: BTreeSet<Finding>,
    notices: BTreeSet<Notice>,
    limit: usize,
}

impl Accumulator {
    fn notice(&mut self, path: &str, code: &str) {
        self.statistics.coverage_notices += 1;
        self.notices.insert(Notice {
            path: path.into(),
            code: code.into(),
        });
        if self.notices.len() > NOTICE_LIMIT {
            self.notices.pop_last();
        }
    }

    fn merge(&mut self, result: FileResult) {
        self.statistics.files_scanned += u64::from(result.scanned);
        self.statistics.bytes_read += result.bytes_read;
        self.statistics.binary_files += u64::from(result.binary);
        self.statistics.baseline_suppressed += result.baseline_suppressed;
        self.statistics.allowlist_suppressed += result.allowlist_suppressed;
        for notice in result.notices {
            self.notice(&notice.path, &notice.code);
        }
        for finding in result.findings {
            *self
                .severity_counts
                .entry(finding.severity.to_string())
                .or_insert(0) += 1;
            self.highest_severity = self.highest_severity.max(Some(finding.severity));
            // Once full, late-sorting findings need no tree-node allocation.
            // Severity accounting still covers every observed finding.
            if self.findings.len() == self.limit
                && self.findings.last().is_some_and(|last| &finding > last)
            {
                self.statistics.findings_omitted += 1;
            } else {
                self.findings.insert(finding);
                if self.findings.len() > self.limit {
                    self.findings.pop_last();
                    self.statistics.findings_omitted += 1;
                }
            }
        }
    }
}

#[derive(Default)]
struct FileResult {
    findings: Vec<Finding>,
    notices: Vec<Notice>,
    scanned: bool,
    binary: bool,
    bytes_read: u64,
    baseline_suppressed: u64,
    allowlist_suppressed: u64,
}

/// Scan only regular files. Never execute source, contact providers, or mutate input.
/// Use a quiescent snapshot: directory replacement races are not a sandbox boundary.
pub fn scan(options: &ScanOptions, config: &Config, baseline: &Baseline) -> Result<Report> {
    ensure!(
        (1..=64).contains(&options.threads),
        "threads must be between 1 and 64"
    );
    ensure!(
        (1..=64 * 1024 * 1024).contains(&options.max_file_bytes),
        "max-file-bytes must be between 1 and 67108864"
    );
    ensure!(
        options.max_total_bytes > 0,
        "max-total-bytes must be positive"
    );
    ensure!(
        (1..=1_000_000).contains(&options.max_files),
        "max-files must be between 1 and 1000000"
    );
    ensure!(
        (1..=100_000).contains(&options.max_findings),
        "max-findings must be between 1 and 100000"
    );
    baseline.validate()?;
    let root = options
        .root
        .canonicalize()
        .context("cannot resolve scan root")?;
    ensure!(root.is_dir(), "scan root must be a directory");
    let rules = RulePack::compile(config)?;
    let policy = Policy::compile(config, rules.known_ids())?;
    let mut accumulator = Accumulator {
        statistics: Statistics::default(),
        severity_counts: BTreeMap::new(),
        highest_severity: None,
        findings: BTreeSet::new(),
        notices: BTreeSet::new(),
        limit: options.max_findings,
    };
    let work = discover(&root, options, &policy, &mut accumulator);
    let accumulator = Mutex::new(accumulator);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads)
        .build()
        .context("cannot create worker pool")?;
    pool.install(|| {
        // Regex clones share compiled programs but have independent search caches.
        work.par_iter().for_each_init(
            || rules.clone(),
            |local_rules, file| {
                let result = inspect(file, local_rules, &policy, baseline);
                // A worker panic is a fatal process error, never a misleading partial success.
                accumulator
                    .lock()
                    .expect("result lock poisoned")
                    .merge(result);
            },
        );
    });
    let mut accumulator = accumulator.into_inner().expect("result lock poisoned");
    if accumulator.statistics.findings_omitted > 0 {
        accumulator.notice(".", "finding_limit");
    }
    let findings: Vec<_> = accumulator.findings.into_iter().collect();
    Ok(Report {
        schema_version: SCHEMA_VERSION,
        tool: "prismwarden".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        rulepack_digest: rules.digest.clone(),
        complete: accumulator.statistics.coverage_notices == 0,
        scope: ScanScope {
            include_gitignored: options.include_ignored || options.no_ignore,
            no_ignore: options.no_ignore,
            excluded_globs: config.exclude.clone(),
            disabled_rules: config.disable_rules.iter().cloned().collect(),
            allowlist_entries: config.allow.len(),
            baseline_fingerprints: baseline.fingerprints.len(),
            hard_pruned_directories: PRUNED.iter().map(|s| (*s).to_string()).collect(),
            max_file_bytes: options.max_file_bytes,
            max_total_bytes: options.max_total_bytes,
            max_files: options.max_files,
            max_findings: options.max_findings,
            max_depth: MAX_DEPTH,
        },
        correlations: correlate::analyze(&findings),
        statistics: accumulator.statistics,
        severity_counts: accumulator.severity_counts,
        highest_severity: accumulator.highest_severity,
        findings,
        notices: accumulator.notices.into_iter().collect(),
    })
}

fn discover(
    root: &Path,
    options: &ScanOptions,
    policy: &Policy,
    accumulator: &mut Accumulator,
) -> Vec<Work> {
    if policy.excludes.is_match(".") {
        accumulator.statistics.excluded_by_policy += 1;
        return Vec::new();
    }
    let excluded = Arc::new(AtomicU64::new(0));
    let excluded_entries = Arc::clone(&excluded);
    #[cfg(windows)]
    let filtered_links = Arc::new(AtomicU64::new(0));
    #[cfg(windows)]
    let filtered_link_entries = Arc::clone(&filtered_links);
    let excludes = policy.excludes.clone();
    let filter_root = root.to_path_buf();
    let mut walker = WalkBuilder::new(root);
    walker
        .hidden(false)
        .follow_links(false)
        .parents(false)
        .ignore(false)
        .git_global(false)
        .git_ignore(!options.include_ignored && !options.no_ignore)
        .git_exclude(!options.include_ignored && !options.no_ignore)
        .require_git(false)
        .max_depth(Some(MAX_DEPTH))
        .sort_by_file_path(|a, b| a.cmp(b))
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            // Some Windows reparse points look like directories to the walker.
            // Reject them before descent, not only when consuming yielded entries.
            #[cfg(windows)]
            if entry.file_type().is_some_and(|kind| kind.is_dir())
                && fs::symlink_metadata(entry.path()).is_ok_and(|metadata| is_link(&metadata))
            {
                filtered_link_entries.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            if entry.file_type().is_some_and(|kind| kind.is_dir())
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|file| PRUNED.iter().any(|name| file.eq_ignore_ascii_case(name)))
            {
                return false;
            }
            if relative_path(&filter_root, entry.path()).is_some_and(|path| excludes.is_match(path))
            {
                excluded_entries.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            true
        });
    if !options.no_ignore {
        walker.add_custom_ignore_filename(".prismwardenignore");
    }
    let mut work = Vec::new();
    let mut reserved = 0u64;
    for entry in walker.build() {
        accumulator.statistics.entries_visited += 1;
        if accumulator.statistics.entries_visited > options.max_files as u64 * 8 {
            accumulator.notice(".", "entry_limit");
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                accumulator.notice(".", "walk_error");
                continue;
            }
        };
        let relative = match relative_path(root, entry.path()) {
            Some(relative) => relative,
            None => {
                accumulator.notice(".", "unsupported_path_encoding");
                continue;
            }
        };
        if entry.error().is_some() {
            accumulator.notice(&relative, "ignore_parse_error");
        }
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(_) => {
                accumulator.notice(&relative, "metadata_error");
                continue;
            }
        };
        if is_link(&metadata) {
            accumulator.statistics.symlinks_skipped += 1;
            continue;
        }
        if metadata.is_dir() {
            if entry.depth() == MAX_DEPTH {
                accumulator.notice(&relative, "depth_limit");
            }
            continue;
        }
        if !metadata.is_file() {
            accumulator.statistics.special_files_skipped += 1;
            continue;
        }
        if work.len() >= options.max_files {
            accumulator.notice(".", "file_limit");
            break;
        }
        let content_notice = if metadata.len() > options.max_file_bytes {
            Some("oversized_file")
        } else if metadata.len() > options.max_total_bytes.saturating_sub(reserved) {
            Some("byte_budget")
        } else {
            reserved += metadata.len();
            None
        };
        // Even when content is unaffordable, filename and permission signals matter.
        work.push(Work {
            absolute: entry.path().to_path_buf(),
            relative,
            metadata,
            content_notice,
        });
    }
    accumulator.statistics.excluded_by_policy += excluded.load(Ordering::Relaxed);
    #[cfg(windows)]
    {
        accumulator.statistics.symlinks_skipped += filtered_links.load(Ordering::Relaxed);
    }
    accumulator.statistics.files_scheduled = work.len() as u64;
    work
}

fn inspect(work: &Work, rules: &RulePack, policy: &Policy, baseline: &Baseline) -> FileResult {
    let mut result = FileResult::default();
    let mut candidates = 0;
    let mut emit = |finding: Finding| {
        candidates += 1;
        if candidates > CANDIDATES_PER_FILE {
            return false;
        }
        if policy.allows(&finding.rule_id, &finding.path) {
            result.allowlist_suppressed += 1;
        } else if baseline.contains(&finding.fingerprint) {
            result.baseline_suppressed += 1;
        } else {
            result.findings.push(finding);
        }
        true
    };
    let metadata = match fs::symlink_metadata(&work.absolute) {
        Ok(metadata) if file_io::unchanged(&work.metadata, &metadata) => metadata,
        _ => {
            result.notices.push(Notice {
                path: work.relative.clone(),
                code: "file_changed".into(),
            });
            return result;
        }
    };
    if !rules.inspect_path(&work.relative, unix_mode(&metadata), &mut emit) {
        result.notices.push(Notice {
            path: work.relative.clone(),
            code: "candidate_limit".into(),
        });
        return result;
    }
    if let Some(code) = work.content_notice {
        result.notices.push(Notice {
            path: work.relative.clone(),
            code: code.into(),
        });
        return result;
    }
    let bytes = match file_io::read_snapshot(&work.absolute, &work.metadata) {
        Ok(bytes) => bytes,
        Err(code) => {
            result.notices.push(Notice {
                path: work.relative.clone(),
                code: code.into(),
            });
            return result;
        }
    };
    result.bytes_read = bytes.len() as u64;
    let text = if bytes.contains(&0) {
        None
    } else {
        std::str::from_utf8(&bytes).ok()
    };
    let Some(text) = text else {
        result.binary = true;
        result.notices.push(Notice {
            path: work.relative.clone(),
            code: "non_text_content".into(),
        });
        return result;
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let complete = rules.inspect_content(&work.relative, text, |finding| {
        candidates += 1;
        if candidates > CANDIDATES_PER_FILE {
            return false;
        }
        if policy.allows(&finding.rule_id, &finding.path) {
            result.allowlist_suppressed += 1;
        } else if baseline.contains(&finding.fingerprint) {
            result.baseline_suppressed += 1;
        } else {
            result.findings.push(finding);
        }
        true
    });
    if !complete {
        result.notices.push(Notice {
            path: work.relative.clone(),
            code: "candidate_limit".into(),
        });
    }
    result.scanned = true;
    result
}

fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    if relative.as_os_str().is_empty() {
        return Some(".".into());
    }
    relative
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()
        .map(|parts| parts.join("/"))
}

fn unix_mode(metadata: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

#[cfg(all(test, unix))]
mod path_tests {
    use super::relative_path;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::Path;

    #[test]
    fn invalid_utf8_relative_paths_are_never_lossily_normalized() {
        let root = Path::new("snapshot");
        let path = root.join(OsString::from_vec(vec![0xff, b'a']));
        assert!(relative_path(root, &path).is_none());
    }
}
