# Architecture

## Data flow

```text
explicit trusted policy + reviewed baseline
                   │
                   ▼
       validate → compile rule pack
                   │
                   ▼
      sorted, scope-aware discovery
        │    budgets + coverage notices
        ▼
  private Rayon worker pool
        │
        ├─ artifact / Unix mode checks
        ├─ bounded regular-file reads
        ├─ UTF-8 / NUL / race checks
        ├─ shared RegexSet shortlist
        ├─ capture validation + entropy gates
        └─ allowlist → baseline → redacted Finding
                   │
                   ▼
      bounded deterministic aggregation
                   │
                   ├─ exposure review hypotheses
                   ├─ coverage / severity gate
                   └─ text / JSON / SARIF / Markdown
```

The crate exposes the same engine used by the CLI. `ScanOptions`, `Config`, and `Baseline` are explicit inputs. A scan does not inherit a global Rayon pool or environment-based rule configuration. Reports have no timestamps, elapsed timings, absolute root paths, or worker-order identifiers. JSON records the declared scope and limits. Severity counts and the highest observed severity include findings omitted by the global retention cap, so truncation cannot hide a known policy violation even when incomplete coverage is explicitly waived.

## Modules

| Module | Responsibility |
|---|---|
| `engine` | Input scope, admission budgets, safe-ish regular-file I/O, concurrency, bounded aggregation |
| `file_io` | Shared bounded regular-file reads, link/reparse rejection, pre/post-read metadata checks |
| `rules` | Built-in/custom rule compilation, regex prefilter, contexts, entropy, coordinates |
| `config` | Strict TOML parsing, rule-ID validation, globs, reasoned allowlists |
| `baseline` | Size-bounded parsing and fingerprint-only reviewed suppressions |
| `model` | Stable serializable records, severity, fingerprints, policy exit semantics |
| `correlate` | Bounded, deterministic co-occurrence and path-context hypotheses |
| `output` | Redacted serializers, terminal/Markdown escaping, URI encoding, atomic files |
| `main` | CLI orchestration; no independent detector implementation |

## Performance model

- The walker admits at most `max_files` descriptors and reserves content bytes in deterministic traversal order. Worker scheduling cannot decide which files consume the total-byte budget.
- No whole-repository content buffer is retained. Each worker holds at most one bounded file buffer; a monotonic Unicode position cursor avoids a separate line-offset index and repeated long-line rescans.
- A single compiled `RegexSet` shortlists relevant content rules; only matching rules perform capture extraction. Worker-local clones share compiled regex programs while keeping independent search caches. Allowlist globs are grouped by rule ID instead of checking every unrelated entry for every finding.
- Rust's regex engine avoids catastrophic backtracking. Custom patterns are limited to 4 KiB, per-regex compiled size to 2 MiB, the combined set to 32 MiB, and custom-rule count to 64. The engine is still subject to workload-dependent CPU costs; there is no hard per-scan wall-clock deadline.
- Entropy uses a fixed 256-counter histogram. It is evaluated only after a syntactic candidate is found.
- Each file emits at most 2,048 candidates and attempts at most 32,768 raw content matches, including candidates discarded by capture, entropy, placeholder, or pinning filters. The global result set retains the lexicographically first `max_findings` locations using a `BTreeSet`, independent of worker order. Rejected candidates beyond a limit become coverage gaps, never silent success.
- Coverage notice storage is capped at 512 unique entries; the total count remains visible. File and entry limits stop enormous traversals; directory depth is capped at 64.
- Correlations use sets/maps and bounded path-ancestor walks, not an all-pairs graph. At most three review hypotheses are emitted, each with at most 16 member fingerprints. Samples retain complete supporting pairs, so a hash-order truncation cannot remove one side of the hypothesis.

Approximate engine-owned memory is `O(files × path_length + threads × (file_bytes + per_file_candidates) + retained_findings + compiled_rules)`. The traversal/ignore libraries add their own storage: sorted traversal can buffer an individual directory, and ignore rules are not covered by the content-byte budget. These are not hard process-RSS limits. Extreme directory fan-out, huge ignore files, or aggressive user-selected budgets can still exhaust a small machine.

Release builds use thin LTO, one codegen unit, and stripped symbols. Performance claims should be measured on a representative corpus; [the recorded synthetic throughput](PERFORMANCE.md) is not a production benchmark.

## Identity and determinism

Finding identity is a BLAKE3 derive-key hash with the public domain string `prismwarden.finding.v1`, over length-delimited rule ID, normalized relative path, and matched evidence. Line numbers are deliberately excluded. Artifact identities use their rule ID as evidence.

Consequences:

- Moving the whole checkout or inserting lines does not change a finding identity.
- Moving a file, changing the matched credential, or changing the rule ID does.
- The same value repeated within one file has one baseline identity but may have several reported locations.
- A private-key header rule fingerprints the header, not the entire key. Replacing a private key with the same header at the same path does **not** invalidate that rule's baseline. Do not baseline private key material.
- The public derive-key string is domain separation, **not a secret key**. Digests may permit guessing attacks.

The rule-pack digest binds serialized policy, active metadata/pattern definitions, and the package version. It is diagnostic provenance, not a signed binary attestation. For exact code identity, retain the repository commit and the artifact checksum.

## File I/O and races

Discovery uses `symlink_metadata`, rejects links/reparse points, and admits regular files only. Matching policy directories are pruned, not just skipped in the result loop. Hard-pruned names apply to directories, not unrelated regular files with those names. Content-budget rejections are scheduled for path/permission inspection without reading their content.

Workers recheck discovery metadata, open without following the final symlink on supported platforms, verify regular-file type and reserved length, and read at most the reserved length plus one byte. After reading, both the open handle and the pathname are checked again. Length, modification metadata, and Unix device/inode/change-time differences are coverage errors. The same bounded no-follow/nonblocking I/O protects explicit policy and baseline loading.

This catches common accidental changes and same-size Unix file substitutions. It does not prove immutable content, detect every same-length rewrite, or bind every ancestor path to an open directory handle. Windows checks modification/creation metadata but does not claim a strong open-handle file-ID comparison. **Use an immutable/quiescent snapshot if another process might mutate the tree.**

Output is staged in a temporary file in the destination directory, synced, then persisted atomically. Baselines use no-clobber persistence unless explicitly forced. Unix output files inherit the temporary file's owner-only permissions. Parent directory syncing, cross-platform ACL hardening, secure memory erasure, and crash-proof filesystem guarantees are not claimed.
