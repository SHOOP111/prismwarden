# Synthetic performance measurement

## Current measurement harness

`examples/throughput.rs` measures five freshly generated synthetic corpora:

| Corpus | Files | Expected findings | Purpose |
|---|---:|---:|---|
| `large_low_hit` | 384 | 24 | Roughly 50 MiB of easy source-like text, preserving the original smoke workload |
| `tiny_files` | 1,024 | 64 | Discovery, metadata, and per-file overhead |
| `dense_findings` | 64 | 2,048 | Capture extraction, hashing, coordinates, and aggregation |
| `long_unicode_lines` | 96 | 96 | Long Unicode lines and code-point location tracking |
| `entropy_rejects` | 64 | 0 | Many syntactic candidates rejected by entropy gates |

Each worker count (1, 2, 4) gets one warm-up and **five measured rounds with rotated worker-count order**. Artifacts retain raw samples, median/minimum/maximum seconds, and throughput calculated from the median. Every scan must be complete and find the expected signals; hashes of the entire report must agree across worker counts and rounds. Serialization, determinism checking, and corpus creation are outside the timed region. Policy/rule compilation, pool creation, discovery, reads, matching, aggregation, and correlations are inside it.

The optional `baseline_ref` workflow input checks out a trusted branch or **full 40-character commit SHA**, copies the exact current harness into it, and runs both versions on the same runner. Baseline measurements and commit identity are retained beside current results. The baseline must support the harness APIs/dependencies. These are sequential warm-cache measurements on a shared host, not causal performance proof or statistically independent confidence intervals.

## Historical single-sample result

The original, narrower harness was measured entirely on [GitHub Actions run 41509396044](https://github.com/SHOOP111/prismwarden/actions/runs/41509396044), commit `ffd3e54fdaac6d457c54340657488878334cf813`.

## Corpus and environment

- 384 freshly generated UTF-8 text files, totaling 52,532,208 bytes (about 50.1 MiB).
- Mostly repeated, non-sensitive source-like text; 24 files contain one synthetic token-shaped value each.
- Ubuntu hosted runner, 4 logical CPUs, AMD EPYC 9V74 virtualized host.
- Rust 1.99.1; release profile with thin LTO.
- Each measurement includes policy/rule compilation, discovery, reading, detection, aggregation, and correlations. Corpus generation and JSON serialization are outside the timed region.
- All three scans were complete and found all 24 synthetic signals.

| Workers | End-to-end seconds | MiB/s |
|---:|---:|---:|
| 1 | 0.1289 | 388.6 |
| 2 | 0.0688 | 727.9 |
| 4 | 0.0459 | 1,091.8 |

## Important limitations

This is **one short synthetic run per worker count**, in increasing order, on a shared virtual machine. The freshly written corpus is likely cached; later scans benefit from warm caches. The repetitive, low-hit corpus is intentionally easy for the regex prefilter. These numbers are not cold-storage performance, statistical confidence bounds, real-repository throughput, or a comparison against other scanners. Dense findings, custom rules, network filesystems, many tiny files, and large directory fan-out can perform very differently.

The purpose is to retain a reproducible smoke measurement and expose obvious performance/detection regressions—not to market a universal throughput guarantee.

## Re-run without compiling locally

```text
gh workflow run performance.yml --ref your-branch
# Optional identical-harness comparison:
gh workflow run performance.yml --ref your-branch -f baseline_ref=FULL_40_CHARACTER_SHA
gh run list --workflow performance.yml
gh run watch RUN_ID --exit-status
gh run download RUN_ID --name synthetic-performance --dir .remote-artifacts/performance
```

The artifact contains raw JSON samples and summaries, runner CPU information, the compiler version, the exact current commit, and optional baseline identity/results. `examples/throughput.rs` generates the corpus on the runner; no user source tree is uploaded.
