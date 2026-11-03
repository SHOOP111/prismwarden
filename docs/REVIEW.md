# Repository-wide hardening review

## Scope and approach

Reviewed every production Rust module, all integration/unit/property/CLI tests, the benchmark example, manifest and locked dependency inventory, all GitHub workflows/helper scripts, repository policy, contribution/security guidance, and engineering documentation. License texts and repository metadata were checked for packaging consistency. Git internals and previously downloaded runner artifacts are not application source.

This is an engineering review, **not an external security certification or proof that every defect is eliminated**. Local work consists only of reading/editing files, Git operations, and downloading/viewing runner artifacts. Formatting, dependency/security checks, compilation, test execution, documentation builds, workflow lint, packaging, and benchmarks run exclusively on GitHub-hosted runners.

## Changes from the reviewed baseline

| Area | Issue / opportunity | Resolution |
|---|---|---|
| Policy scope | Default glob behavior let `*` span directory boundaries and changed backslash interpretation by OS | One explicit directory-aware glob compiler shared by exclusions, allowlists, and custom-rule paths; cross-platform regressions and migration guidance |
| Target ignore files | Git-only ignore bypass could not bypass target `.prismwardenignore` reductions | Explicit `--no-ignore`, recorded in every report's scope; policy exclusions and hard pruning remain |
| Windows traversal | Directory-like reparse points should be rejected before descent, not only after yielding | Pre-descent metadata filter and hosted Windows junction regression |
| Coordinates | Standalone CR was counted as a column, not a line break | Monotonic Unicode cursor recognizes CR, LF, and CRLF, including pairs split between captures; property/reference and SARIF checks |
| Assigned secrets | Common camelCase names, AWS secret-access-key assignments, declarations, and later compact-JSON fields were missed | Extend SEC009 while retaining entropy checks and distinguishing selected unquoted environment expressions from quoted literals |
| Workflow inputs | Direct-expression matching missed fallback expressions and selected untrusted head-ref/commit fields | Extend CI005 with contextual positive/negative tests; findings remain lexical review prompts |
| Baseline API | A caller could mark a truncated public report complete before converting it | Reject inconsistent notices/counters, unsupported report schemas, invalid fingerprints, and oversized baselines |
| Rule-pack provenance | Detector scope/capture/entropy/pinning settings were not all bound explicitly | Length-framed v2 digest includes detector settings and kinds; finding identity remains v1 |
| Unicode scanning | Combined Unicode word boundaries forced a very slow regex-set path on non-ASCII text | Broaden only built-in shortlists; preserve original capture regexes and custom patterns; optimized/reference property tests and measured workload-specific 34–62× improvement |
| Aggregation | Full retention sets inserted and immediately removed known late-sorting candidates | Compare with retained maximum first; retain all observed severity accounting and deterministic results |
| Artifact checksums | Entire files were loaded to hash, and every nested file named SHA256SUMS was skipped | Streaming hashing; exclude only the root manifest; deterministic LF output; reject symlinks and ambiguous checksum filenames |
| License inventory | Packaging helpers lacked regression coverage and could silently miss declared license files or collide basenames | Testable helper API, explicit error handling, source/destination confinement, deterministic inventory, collision checks |
| Workflow quality | Workflows were not linted; MSRV ran a type check only; checkout/upload used deprecated Node 20 actions | Version-pinned actionlint with shell checks; full minimum-Rust and doctest execution; reviewed full-SHA Node 24 checkout/upload updates with no write-permission expansion |
| SARIF conformance | Official-schema smoke test covered one ordinary successful result | Validate empty, finding-bearing, incomplete, and truncated scans; assert URI encoding, Unicode coordinates, exit codes, and redaction |
| Benchmark credibility | One easy corpus and one increasing-order sample per thread count | Five corpora, warm-ups, five rotated samples, medians/ranges, full-report determinism checks, optional identical-harness baseline comparison |

The new regressions live primarily in `tests/deep_audit.rs` and `.github/scripts/test_helpers.py`, with optimized/reference Unicode prefilter coverage in `src/rules.rs`; existing tests remain in place. No production dependencies were added or broadly upgraded merely to generate churn.

## Behavior and compatibility notes

- **Review existing globs.** Use `**/*.txt` instead of `*.txt` when recursion is intentional. The previous broad matching can no longer silently extend a suppression across directories. A matching directory still excludes its whole subtree.
- `--no-ignore` expands input scope, so it may expose findings, binary-content gaps, or budget limits that default ignore scope hid. It does not promise to scan hard-pruned directories, Git history, archives, or alternate streams.
- Reports gain an additive `scope.no_ignore` field, defaulting to false when deserializing earlier reports. Report schema and finding/baseline identity remain version 1. Rule-pack digest values change to the v2 construction.
- New detector coverage can surface additional findings. Entropy and lexical matching still have false positives and misses; this is not semantic configuration/taint analysis.
- Baseline consistency checks validate visible report invariants, not authenticity. Do not accept fabricated external reports as trusted evidence.

## Validation evidence

GitHub Actions is the only validation environment. [CI run 41590766037](https://github.com/SHOOP111/prismwarden/actions/runs/41590766037) passed the complete Linux/Windows/macOS test/build/package matrix, Rust 1.88 tests, rustfmt, Clippy, rustdoc, official SARIF schema checks, repository self-audit, and workflow lint for the optimized engine. The synthetic comparison passed in [run 41590770367](https://github.com/SHOOP111/prismwarden/actions/runs/41590770367); raw samples and limitations are in [PERFORMANCE.md](PERFORMANCE.md). Earlier failed runs are part of the feedback loop, not evidence of passing checks. Modernized workflows passed again in [CI run 41591447240](https://github.com/SHOOP111/prismwarden/actions/runs/41591447240), [RustSec audit 41591452608](https://github.com/SHOOP111/prismwarden/actions/runs/41591452608), [remote maintenance 41591457694](https://github.com/SHOOP111/prismwarden/actions/runs/41591457694), and [identical-harness benchmark 41591462512](https://github.com/SHOOP111/prismwarden/actions/runs/41591462512). A runnable public API documentation example is also included and checked on stable/MSRV runners before delivery.

## Reviewed boundaries retained intentionally

- The scanner stays offline, read-only with respect to source inspection, and free of provider credential testing or source execution. Explicit output paths are the only requested writes.
- Reports omit matched values/source snippets but still reveal paths, custom descriptions, and guessable public fingerprints. Uploads require review.
- Coverage and severity gates stay separate: incomplete scans default to exit 3; waiving coverage does not hide observed high-severity results omitted by retention.
- Correlations remain bounded, deterministic hypotheses using complete supporting pairs. They do not alter the severity gate or claim reachability.
- Sorted traversal, independent regex caches, bounded file reads, grouped allowlists, and capped findings/notices are preserved. Memory/CPU bounds are not a hard RSS or wall-clock sandbox.
- No-follow final-component I/O and metadata checks do not contain hostile concurrent ancestor replacement or prove immutable content. Scan a quiescent snapshot.
- Windows file identity/ACL checks, crash-durable directory syncing, secure memory erasure, streaming report serialization, semantic parsers, Git-history analysis, and full fuzz/coverage campaigns remain outside the current implementation. See [THREAT_MODEL.md](THREAT_MODEL.md).
- Checksums are integrity aids, not independent signatures or reproducible-build attestations. Stable toolchains and hosted runners remain trusted, and unsigned preview release binaries do not automatically update when a review branch is pushed.

## Future work, not unverified claims

Useful next steps include representative privately held corpora, profiler-guided optimization, longer fuzz campaigns on runner-hosted infrastructure, per-format streaming output, isolated/limited ignore parsing, open-directory-handle traversal, robust Windows file-ID comparison, and semantic configuration analysis. Each needs its own threat-model and compatibility review; none is claimed complete by this pass.
