# Threat model

## Intended use

Review a source checkout, export directory, or deployment bundle **you own or are authorized to inspect**, before publication or CI promotion. Prefer a frozen snapshot. PrismWarden reports evidence to the operator; it does not revoke keys or modify input.

## Assets and boundaries

| Asset / threat | Mitigation | Remaining limitation |
|---|---|---|
| Source secrets in reports | Findings omit raw matches and snippets | Paths, custom descriptions, and fingerprints remain sensitive |
| Accidental provider contact | No networking dependencies or subprocess execution in the scanner engine | OS/network-mounted file access, dependency resolution, CI and report upload are outside this guarantee |
| Terminal / Markdown injection | Escape controls, bidi markers, and Markdown punctuation; percent-encode SARIF paths | JSON consumers must escape values appropriately in their own UI |
| Catastrophic regex backtracking | Rust regex engine, pattern/compiled-size caps | CPU use is workload-dependent; no wall-clock timeout |
| Memory exhaustion | Bounded engine-owned files/bytes/workers/candidates/results/notices | Aggressive budgets, long paths, traversal sorting/ignore-rule buffers, allocator overhead |
| Traversal loops / symlink escape | Skip links/reparse points; final-component no-follow opens | Concurrent hostile ancestor-directory replacement is not contained |
| FIFO/device hangs | Skip special files; Unix nonblocking opens | Unresponsive filesystems/mounts can still block |
| Incomplete scan reported as safe | Explicit coverage notices; exit 3 by default; refuse incomplete baselines | Operator may intentionally waive coverage or exclude meaningful input |
| Malicious target policy | No implicit TOML policy loading; no inline suppressions | Target ignore files still influence declared scope |
| Report clobbering | Same-directory temporary file, symlink rejection, atomic persistence | Destination ancestors and ACLs must be trusted; filesystem crash semantics vary |
| Credential guessing from fingerprints | Domain-separated, length-delimited BLAKE3 | Public unkeyed digest is not confidentiality; low-entropy evidence is guessable |
| Supply-chain drift | Checked-in lockfile, pinned Actions, minimal permissions, scheduled RustSec checks | Hosted runners, registries, toolchains, upstream maintainers remain trusted |

## Explicit non-goals

- No stealth, persistence, exploit delivery, anonymity infrastructure, anti-forensics, or monitoring evasion.
- No remote discovery, credential testing, endpoint enumeration, or account access.
- No browser/session/cookie extraction or password-vault decryption.
- No Git history analysis, archive extraction, document metadata decoding, malware detection, or semantic code taint analysis.
- No promise that a passing scan establishes compliance or absence of sensitive information.
- No cryptographic erasure of matched values from process memory. Content necessarily exists in ordinary heap buffers while scanning; OS paging and crash dumps are outside the tool's control.
- No full Windows ACL audit, Unix ACL audit, alternate-data-stream enumeration, or filesystem-sandbox guarantee.

## Interpreting hypotheses

`EXP001` joins a credential signal and selected risky workflow settings in the same tree. It does not establish that the workflow reads the credential.

`EXP002` joins sensitive material at/below a Dockerfile directory with a broad copy. Actual build contexts and `.dockerignore` are not resolved. Sensitive material may be excluded or belong to another build.

`EXP003` joins debug and public-bind settings in the same file. They may belong to distinct services or inactive profiles.

These are review prompts, never proof of compromise. They do not independently alter severity-gate results.

## Responsible operation

1. Scan a trusted snapshot and inspect scope/exclusions first.
2. Treat credential-shaped findings as potentially live until reviewed privately.
3. Revoke exposed credentials before rewriting repository history or creating a baseline.
4. Investigate incomplete coverage; do not blindly add `--allow-incomplete` to CI.
5. Keep baseline and policy changes review-protected.
6. Review reports before publishing, even though matched values are omitted.
7. Run the executable with minimum necessary filesystem access.

For security defects in PrismWarden itself, follow [SECURITY.md](../SECURITY.md).
