# Contributing: remote-only verification

This project was created with a strict workflow: **no local compilation or test execution**. Editing files, Git operations, and downloading CI artifacts happen locally; dependency resolution, formatting, compilation, tests, linting, documentation builds, and executable packaging happen on GitHub-hosted runners.

## Standard development loop

1. Edit code and add synthetic regression tests. Never add live credentials or private scan corpora.
2. Commit and push a branch; open a pull request. Alternatively, dispatch CI on a pushed branch:

   ```text
   gh workflow run ci.yml --ref your-branch
   gh run list --workflow ci.yml
   gh run watch RUN_ID --exit-status
   gh run view RUN_ID --log-failed
   ```

3. If formatting fails, download the runner-generated patch:

   ```text
   gh run download RUN_ID --name remote-formatting --dir .remote-artifacts/format
   git apply .remote-artifacts/format/rustfmt.patch
   ```

4. Commit the formatting change and push again. Do not label unrun checks as passing.
5. Download a successful binary artifact if you want to use the tool without installing Rust.

## Dependency changes

Change `Cargo.toml`, push a branch, then resolve the lockfile remotely:

```text
gh workflow run maintenance.yml --ref your-branch
gh run list --workflow maintenance.yml
gh run watch RUN_ID --exit-status
gh run download RUN_ID --name remote-maintenance --dir .remote-artifacts/maintenance
```

Copy the generated `Cargo.lock` into the repository, review it, apply the formatting patch if nonempty, commit, and push. The maintenance workflow has read-only repository permissions and cannot silently commit changes. Normal CI always uses `--locked`.

## Checks

- Stable Rust on Linux, Windows, and macOS: unit, integration, property, CLI, and doctests; optimized release compilation.
- Declared minimum Rust: locked unit, integration, property, CLI, example, and documentation tests, not only a type check.
- Workflows: version-pinned actionlint validates expressions and shell commands.
- Quality: rustfmt, Clippy with warnings denied, rustdoc with warnings denied, independent SARIF schema validation, self-audit of this repository.
- Security: pinned `cargo-audit` with warnings denied, backed by the current RustSec database. This check intentionally changes as advisories evolve.
- Distribution helpers: streaming/recursive checksum correctness and cross-platform newline stability; deterministic inventory ordering; declared-license handling; source/destination confinement; symlink and filename-ambiguity rejection.
- Synthetic tests cover all built-in detectors, redaction, Unicode coordinates, baseline drift, context filters, custom-rule validation, deterministic parallel truncation, resource gates, ignore semantics, CLI exit codes, output clobber protection, consistent directory-aware policy globs, ignore bypass scope, mixed CR/LF coordinates, baseline report consistency, notice truncation, Unix symlink/FIFO behavior, and Windows directory junctions.

The [repository-wide review](docs/REVIEW.md) records the scope of the latest hardening pass and remaining limitations. Benchmark changes should retain raw repeated samples and compare the same harness/corpus, not a single best-case measurement.

No coverage percentage, fuzz-campaign result, formal verification, or reproducible-build claim is made without corresponding measurement.

## Review expectations

- New rules need positive and negative tests, scope notes, false-positive discussion, and remediation text.
- Keep evidence out of all serializers and error paths.
- Preserve deterministic ordering and bounded intermediate storage.
- New suppression mechanisms require an explicit threat-model review.
- Avoid `unsafe`; the crate forbids it. Dependencies may contain audited or unaudited unsafe code of their own.
- Action updates must remain pinned to full commit SHAs. Fork pull requests receive no write-capable token and no repository secrets from these workflows.
- Use a private GitHub security advisory for vulnerabilities; never paste live credentials into issues.
