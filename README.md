# PrismWarden

**Find the exposure before you publish the tree.**

[![CI](https://github.com/SHOOP111/prismwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/SHOOP111/prismwarden/actions/workflows/ci.yml)
[![Security audit](https://github.com/SHOOP111/prismwarden/actions/workflows/security.yml/badge.svg)](https://github.com/SHOOP111/prismwarden/actions/workflows/security.yml)

PrismWarden is an **offline, read-only OPSEC auditor written in Rust**. It brings credential detection, automation hardening, runtime configuration review, privacy checks, and compound-exposure hypotheses into one deterministic CLI.

It does **not** validate credentials against providers, execute your project, inspect your browser, scan the network, or send telemetry. It is a defensive review tool—not a guarantee of safety and not an evasion framework.

## What makes it useful

- **29 built-in rules** across secrets, CI, runtime, privacy, and sensitive artifacts.
- **Privacy-conscious evidence:** location + remediation + BLAKE3 fingerprint; matched values and source snippets never enter reports.
- **Compound-exposure review:** credentials near risky automation; sensitive material near broad container copies; debug mode alongside all-interface listeners. Explicitly labeled hypotheses, not invented exploit paths.
- **Bounded parallel scanning:** shared regex-set prefilter, entropy gates, deterministic admission, private Rayon pool, capped candidate/report accumulation.
- **Fail-closed coverage:** oversized, unreadable, non-UTF-8/binary, changed, and truncated input produce visible coverage notices and exit `3` by default.
- **Auditable policy:** explicit TOML, path/rule allowlists with required reasons, severity overrides, bounded custom Rust-regex rules. No inline suppression directives.
- **Reviewable baselines:** fingerprint-only JSON; stable across line shifts; changed token values normally reappear; incomplete scans cannot create baselines. Header-only/path-only identity exceptions are documented.
- **Four report formats:** terminal-safe text, JSON, SARIF 2.1.0, and escaped Markdown.
- **Filesystem hygiene:** no symlink traversal during ordinary discovery; regular-file checks; Unix no-follow/nonblocking opens; Windows reparse-point checks; atomic report writes.
- **GitHub-only build workflow:** Linux, Windows, and macOS tests/builds; formatting, Clippy, documentation, SARIF schema validation, and dependency auditing run on hosted runners.

## Get a binary without compiling locally

Download the platform ZIP from the [v0.1.0 preview release](https://github.com/SHOOP111/prismwarden/releases/tag/v0.1.0), or use the latest verified CI artifacts:

1. Open [GitHub Actions → CI](https://github.com/SHOOP111/prismwarden/actions/workflows/ci.yml).
2. Select a successful run for the commit you want.
3. Download the `prismwarden-ubuntu-latest`, `prismwarden-windows-latest`, or `prismwarden-macos-latest` artifact.
4. Extract it; verify the included `SHA256SUMS` against the executable. On Unix, you may need `chmod +x prismwarden` after extraction.

Binaries are runner-native and unsigned; CI artifacts have finite retention. Packages include `BUILD-INFO.txt`, recursive `SHA256SUMS`, a dependency inventory, available upstream license texts, and the documentation. Checksums detect accidental corruption; they are **not** independent provenance or signatures. The preview release is early-stage software, not an audited production certification. There is no crates.io release yet.

```text
prismwarden --help
prismwarden rules
prismwarden scan ./project
prismwarden scan ./project --include-ignored --format json --output .prismwarden/report.json
prismwarden scan ./project --format sarif --output .prismwarden/report.sarif
prismwarden scan ./project --format markdown --output .prismwarden/report.md
```

Output paths are relative to the **current working directory**, not the scan root. No source files are modified. Only explicitly requested report/baseline paths are written.

### Review and baseline existing debt

```text
prismwarden scan ./project --fail-on none
prismwarden baseline create ./project --output .prismwarden/baseline.json
prismwarden scan ./project --baseline .prismwarden/baseline.json --fail-on high
```

Baseline creation acknowledges **every current finding** in the declared scope. Review the report first. Baselines are not permission to keep live credentials: revoke exposed credentials before suppressing anything. Existing baselines are never overwritten unless `--force` is supplied.

### Use a trusted policy explicitly

```text
prismwarden scan ./project --config ./trusted-policy.toml --threads 4
```

```toml
schema_version = 1
exclude = ["assets/**", "generated/**"]

[severity]
CI002 = "high"

[[allow]]
rule = "SEC009"
path = "tests/fixtures/**"
reason = "Reviewed synthetic fixtures; no live credentials"
```

See [configuration](docs/CONFIGURATION.md) for custom rules and resource controls.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No unsuppressed finding meets the chosen threshold |
| `1` | At least one unsuppressed finding meets the threshold (default: high) |
| `2` | Invalid usage/configuration or operational failure |
| `3` | Coverage incomplete; takes precedence over finding severity |

`--fail-on none` disables the severity gate, **not** the coverage gate. `--allow-incomplete` explicitly waives the coverage gate; it does not remove notices and is unavailable for baseline creation.

## Scope and honest limitations

Default scope is regular UTF-8 text files, including hidden files, subject to `.gitignore`, repository `.git/info/exclude`, `.prismwardenignore`, explicit exclusions, and hard-pruned directories. `--include-ignored` bypasses Git ignore rules only. Parent/global ignore files are not imported. `.git`, `.hg`, `.svn`, `target`, `node_modules`, `.venv`, and `.prismwarden` are always pruned below the root.

“Complete” means **complete within this declared scope**, not every file on disk. Symlinks and special files are intentionally outside scope and counted. Binary/non-UTF-8 files receive filename checks but produce coverage notices because content was not inspected. Archives, images, PDFs, office documents, Git history, UTF-16, ACLs, alternate streams, and live process memory are not decoded or audited.

Configuration checks use lexical patterns, not full YAML/HCL/Docker/shell semantic analysis. Findings may occur in comments or inactive configuration. Credential-shaped values may be synthetic. Entropy is a heuristic. A clean result is not proof that secrets are absent.

**Reports can still be sensitive.** Paths, custom rule descriptions, and findings reveal structure. Fingerprints are unkeyed digests, not encryption; low-entropy inputs can be guessed. Review before uploading any report, including SARIF. The scanner's no-network property does not apply to dependency downloads or GitHub Actions, which necessarily use the network.

Scan a quiescent, trusted snapshot. This is **not a filesystem sandbox against a hostile process replacing ancestor directories while a scan is running**. See the [threat model](docs/THREAT_MODEL.md).

## Engineering documentation

- [Architecture and performance model](docs/ARCHITECTURE.md)
- [Measured synthetic throughput and its limitations](docs/PERFORMANCE.md)
- [Configuration and rule catalog](docs/CONFIGURATION.md)
- [Threat model and security boundaries](docs/THREAT_MODEL.md)
- [Remote-only development](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

## License

MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
