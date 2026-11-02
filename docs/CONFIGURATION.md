# Configuration and rule catalog

## Trust model

Policy is loaded **only** with `--config PATH`. A target repository cannot silently disable rules by adding `prismwarden.toml`. However, ignore files are part of the declared discovery scope: review them on untrusted trees, and consider `--include-ignored`. That flag does not bypass `.prismwardenignore` or hard-pruned directories.

Unknown TOML fields, unknown rule IDs, duplicate custom IDs, invalid regexes/globs, missing allowlist reasons, and unsupported schemas are errors. Configuration files must be UTF-8 and no larger than 1 MiB. Syntax diagnostics deliberately do not echo raw configuration lines.

## Complete example

```toml
schema_version = 1
exclude = ["assets/**", "generated/**"]
disable_rules = ["PRV001"]

[severity]
CI002 = "high"

[[allow]]
rule = "SEC009"
path = "tests/fixtures/**"
reason = "Approved synthetic credential fixtures, reviewed by the repository owner"

[[rules]]
id = "ORG001"
title = "Internal-only distribution marker"
remediation = "Review the document classification before publication."
severity = "medium"
category = "privacy"
pattern = 'INTERNAL-ONLY: ([A-Z0-9-]{8,64})'
capture = 1
path = "documents/**"
```

Relative paths always use `/`. Globs are matched against each relative entry; use `directory/**` to exclude a subtree. Matching is case-sensitive except built-in artifact basename checks. Explicit exclusions are intentional scope reductions and do not mark coverage incomplete.

Allowlist entries suppress a particular rule on matching paths. No regular-expression value allowlist or inline source directive exists. Keep allowlists narrow and protected by review. Disabling a rule is also a scope reduction, not a remediation.

Custom-rule categories: `secret`, `automation`, `runtime`, `privacy`, `artifact`. All custom rules are **content regex rules**, regardless of category. Categories affect presentation/correlation and the exact built-in placeholder filter; they do not turn a custom rule into a filename detector.

Custom patterns use [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax). Lookaround and backreferences are unavailable. Multiline/case-insensitive behavior must be requested with flags such as `(?im)`. `capture` defaults to `0` (the whole match). Optional `min_entropy` is a finite Shannon entropy threshold in bits per byte, between `0` and `8`. Optional `path` limits the rule to a glob. Empty-string regexes are rejected. Titles/remediations are trusted user-authored text and appear verbatim in JSON; do not put secrets in them.

## Resource controls

| Flag | Default | Validation / behavior |
|---|---:|---|
| `--threads` | available CPUs, at most 8 | 1–64; private pool |
| `--max-file-bytes` | 2,097,152 | 1–67,108,864 |
| `--max-total-bytes` | 268,435,456 | positive; admitted content budget |
| `--max-files` | 50,000 | 1–1,000,000; traversal entry cap is 8× this |
| `--max-findings` | 10,000 | 1–100,000; retained results |

Fixed limits: depth 64, 2,048 emitted candidates per file, 512 stored coverage notices, 64 custom rules, 4 KiB custom pattern text, 8 MiB baseline file, and 100,000 baseline identities. Candidate limits are applied before baseline/allowlist suppression so a huge suppressed corpus cannot evade work limits.

## Built-in rules

List authoritative active metadata with `prismwarden rules --json` (add `--config` to inspect a customized pack).

| ID | Default | Signal |
|---|---|---|
| SEC001 | critical | PEM/OpenSSH private-key header |
| SEC002 | high | GitHub token shapes |
| SEC003 | high | AWS access key ID shape (not a secret by itself) |
| SEC004 | high | Slack token shapes |
| SEC005 | high | Live Stripe secret/restricted key shapes |
| SEC006 | high | Google API key shape |
| SEC007 | medium | JWT shape; not decoded or signature-validated |
| SEC008 | high | Credentials in common service/HTTP URLs |
| SEC009 | high | High-entropy assigned secret names |
| SEC010 | high | PyPI upload token shape |
| SEC011 | high | npm token shape |
| SEC012 | high | High-entropy literal bearer authorization |
| CI001 | high | Workflow-wide write-all permissions |
| CI002 | medium | External action not pinned to full commit/digest |
| CI003 | high | Privileged pull-request trigger, requiring review |
| CI004 | medium | Checkout credential persistence explicitly enabled |
| CI005 | high | Untrusted event expression in a workflow |
| RUN001 | medium | Broad Docker COPY/ADD |
| RUN002 | high | Privileged container setting |
| RUN003 | medium | All-interface bind address |
| RUN004 | high | Selected TLS-verification bypass settings |
| RUN005 | medium | Debug-enabled configuration |
| RUN006 | high | SSH root login explicitly permitted |
| PRV001 | low | User-specific absolute home path |
| PRV002 | high | Unix group/other permission bits on selected sensitive files |
| ART001 | medium | Real-looking `.env` artifact (template suffixes excluded) |
| ART002 | high | Terraform state / state backup |
| ART003 | low | Desktop metadata artifact |
| ART004 | high | SSH private-key basename / PKCS#12 / KeePass container |

CI rules apply to `.github/workflows/*.yml`/`.yaml` paths beneath the scan root. Docker-copy rules apply to Dockerfile basenames. Selected runtime rules are restricted to common configuration extensions. These are lexical checks, so comments, inactive settings, and unusual syntax can produce false positives or misses.

Exact placeholder matching is intentionally narrow. A value is not exempt merely because it contains `example`, `test`, or `fake`. The generic entropy rule does not detect every low-entropy password. Token formats change; detector maintenance is necessary.

## Baseline semantics

Baseline JSON contains only `schema_version` and sorted `fingerprints`. A baseline is loaded explicitly. It is not tied to absolute checkout paths or line numbers. File renames and changed matched evidence normally produce new identities; header-only and path-only rules are exceptions, as explained in [architecture](ARCHITECTURE.md).

The baseline does not include reports, source code, or raw values. It still deserves access control and review. A committed baseline can be abused to hide existing debt if changes are not protected by code review.

## Coverage codes

| Code | Meaning |
|---|---|
| `walk_error`, `metadata_error`, `read_error` | Traversal or I/O could not be completed |
| `ignore_parse_error` | An ignore file could not be fully interpreted |
| `unsupported_path_encoding` | Relative path cannot be represented losslessly as UTF-8 |
| `file_changed` | Entry type or size changed around opening/reading |
| `oversized_file` | Per-file byte limit exceeded |
| `byte_budget` | Total content reservation exceeded |
| `file_limit`, `entry_limit`, `depth_limit` | Discovery resource ceiling reached |
| `non_text_content` | NUL-containing or invalid-UTF-8 content not decoded |
| `candidate_limit` | Per-file candidate ceiling reached |
| `finding_limit` | Global retained-result ceiling reached |

No raw filesystem diagnostic or source snippet is embedded in notices. A notice is not a vulnerability; it means the scan could not establish full coverage of its declared scope.
