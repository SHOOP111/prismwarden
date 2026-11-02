# Security policy

PrismWarden is an early-stage defensive audit tool. The latest main-branch version receives fixes; there is no security-response SLA or external audit certification.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/SHOOP111/prismwarden/security/advisories/new) for vulnerabilities in this tool. Include a minimal synthetic reproduction, affected commit, operating system, expected behavior, and impact.

Do **not** attach live tokens, private keys, personal scan trees, or unredacted reports. If you accidentally exposed a real credential, revoke it with the provider immediately; reporting it here does not revoke it.

If private reporting is unavailable, open a public issue asking for a private contact method **without disclosing exploit details or sensitive data**.

## Particularly relevant bugs

- Source evidence leaked through output, errors, or artifacts.
- Silent incomplete scans or policy-gate bypasses.
- Unbounded resource consumption beyond the documented limits.
- Unsafe traversal or output behavior beyond the documented snapshot model.
- Suppression mechanisms that exceed their documented scope.

Read [the threat model](docs/THREAT_MODEL.md) before interpreting a behavior as a guarantee. A detector miss or false positive is often a rule-quality issue; report it with synthetic data only.
