# Security Policy

> **Current Status:** `v0.7/v0.8 Public Beta - Paper-First Recommended; no third-party security audit completed yet.`

ClearFills is pre-trade risk firewall and execution software for real brokerage accounts. We treat security bugs as top-priority engineering defects and actively welcome external security reviews, red-team testing, and cryptographic audits of this repository.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for undisclosed security vulnerabilities.**

Please report security issues through either of these private channels:

1. **GitHub Security Advisories (preferred):** [Open a private advisory](https://github.com/clearfills/clearfills/security/advisories/new)
2. **Email:** `security@clearfills.com`

Include as much detail as possible:
- Affected package or file (`clearfills_firewall`, `clearfills_desk`, `clearfills` CLI, `deploy/isolated-worker/`)
- Minimal reproduction steps, proof-of-concept payload, or failing test
- Impact assessment (e.g. policy bypass, signature forgery, replay, live-mode gate bypass)

---

## Response SLA

| Milestone | Target Timeline |
| :--- | :--- |
| Initial acknowledgement | Within 48 hours |
| Triage & severity classification | Within 5 business days |
| Fix & coordinated disclosure | 7-30 days for High/Critical; up to 90 days for Low/Medium |

We will coordinate public disclosure with the reporter and credit researchers by name or handle unless anonymity is requested.

---

## Scope

### In Scope
- Deterministic policy bypasses in `packages/risk-firewall/` (`clearfills_firewall`)
- Ed25519 attestation forgery, RFC 8785 JCS canonicalization mismatches, or nonce replay vulnerabilities
- WebAuthn / Passkey co-sign verification bypasses (`rpIdHash`, `origin`, `UV`, challenge binding)
- Kill-switch bypasses or audit ledger verification flaws
- Fail-closed live-execution gate bypasses (`CLEARFILLS_ALLOW_LIVE`, paper vs. live port/account checks) in `packages/clearfills-desk/`
- Container or privilege-escalation flaws in `deploy/isolated-worker/`

### Out of Scope
- Same-UID local host compromise when an AI coding agent with shell access is deliberately run under the same OS user as `~/.clearfills/` (this is an OS-level trust boundary explicitly documented in [`EXECUTION_THREAT_MODEL.md`](EXECUTION_THREAT_MODEL.md); bypasses of the documented Docker or separate-user isolation *are* in scope)
- Compromised user brokerage credentials or third-party broker API outages
- Social engineering, phishing, or denial-of-service against public documentation sites

---

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `0.7.x` / `0.8.x` | Yes | Public Beta; paper-first recommended |
| `< 0.7.0` | No | Upgrade to latest release |

---

## External Security Reviews

We welcome independent code audits, formal verification of the RFC 8785 / Ed25519 / WebAuthn verification paths, and red-team reports. If you are a security researcher or audit firm interested in reviewing ClearFills, reach out at `security@clearfills.com`.

For the full threat model and deployment hardening checklist, read [`EXECUTION_THREAT_MODEL.md`](EXECUTION_THREAT_MODEL.md).
