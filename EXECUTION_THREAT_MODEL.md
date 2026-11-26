# ClearFills Execution Threat Model

> **Audit Status:** `v0.7/v0.8 Public Beta - Paper-First Recommended; no third-party security audit completed yet.`
> Start with Interactive Brokers Paper Trading (`port 4002`, `DU*` account) and `--dry-run` before connecting live capital.

This document describes the security boundaries, attacker models, and honest limitations of the ClearFills open-core execution firewall (`clearfills_firewall`, `clearfills_desk`, and the `clearfills` CLI). ClearFills is deterministic pre-trade risk software, not an OS sandbox or a hardware wallet.

---

## Architecture & Trust Boundaries

```text
+----------------------------------+        +-----------------------------------+
|  UNTRUSTED ZONE                  |        |  ISOLATED TRUST ZONE              |
|  AI Coding Agent / LLM Runtime   |        |  UID 10001 (Docker) or Separate   |
|  (Claude Code, Codex, Cursor)    |        |  OS User / Tailscale VM           |
|                                  |        |                                   |
|  - Can be prompt-injected        |  MCP/  |  1. Policy Authority (Signer)     |
|  - May have host shell access    +------->+     Holds Ed25519 private key     |
|  - Never holds broker passwords  |  HTTP  |     Uses server UTC clock +       |
+----------------------------------+        |     trusted PortfolioProvider     |
                                            |                                   |
                                            |  2. Execution Worker (Verifier)   |
                                            |     Holds Ed25519 public key only |
                                            |     Verifies WebAuthn Passkey     |
                                            |     Connects to IB Gateway        |
                                            +-----------------+-----------------+
                                                              |
                                                              v (loopback / Tailscale)
                                            +-----------------------------------+
                                            |  IBKR Gateway (4002 paper / 4001) |
                                            +-----------------------------------+
```

ClearFills assumes the AI agent proposing trades is **untrusted** (susceptible to prompt injection, hallucinated sizing, or tool misuse). The firewall's job is to ensure no order reaches a broker unless it satisfies deterministic math, carries a valid single-use Ed25519 attestation, and (when configured) is co-signed by a human operator.

---

## 1. Same-UID Shell Exposure (Critical Local Risk)

**The threat:** If you run an AI coding agent with shell execution privileges (such as Claude Code, Codex CLI, or an IDE terminal) under the **same OS user account** that owns `~/.clearfills/`, `.clearfills_desk/`, or `.clearfills.yaml`, the OS provides zero isolation between the agent and the firewall.

A compromised or prompt-injected agent sharing your UID can:
1. Read `authority_ed25519.pem` and mint valid Ed25519 attestations for arbitrary orders.
2. Delete or overwrite `killswitch.json` to re-enable trading after a halt.
3. Modify `.clearfills.yaml` to raise notional caps or remove stop-loss rules.
4. Connect directly to IB Gateway on `127.0.0.1:4001` without going through ClearFills at all.

**Required mitigations for live capital:**
- **Docker isolation (recommended):** Run `clearfills watch` inside [`deploy/isolated-worker/`](deploy/isolated-worker/). The container runs as a dedicated non-root user (`clearfills:clearfills`, UID `10001`) with a root-owned Docker named volume (`clearfills_state`) and `0600` file permissions. Your host coding-agent user cannot read keys or tamper with `killswitch.json` inside that volume.
- **Dedicated OS user + Unix socket enclave:** Run the policy signer under a separate OS user (e.g. `_clearfills` or `clearfills-signer`) and connect `DeskRuntime` over a permissioned `AF_UNIX` socket (`unix:///var/run/clearfills/signer.sock`) via `enclave_client.py`.
- **Separate Tailscale VM:** Host IB Gateway and `clearfills watch` on a dedicated VM reachable only over Tailscale ACLs, with no coding agent installed on that machine.
- **Shell hygiene:** Never export `CLEARFILLS_ALLOW_LIVE=1` or `CLEARFILLS_API_KEY` in `~/.zshrc` or `~/.bashrc` where any subshell spawned by a coding agent inherits them.

---

## 2. Caller-Supplied State vs. Trusted Broker Snapshot

**The threat:** If `propose_trade` accepted portfolio NAV, current positions, daily realized loss, or wall-clock timestamps from the calling agent, a prompt-injected agent could:
- Report an inflated NAV (e.g. `$50,000,000`) to bypass percentage-based position caps.
- Omit existing positions to bypass concentration limits or stack duplicate orders.
- Supply a backdated or future timestamp to evade daily loss lockouts or extend the 120-second attestation TTL.

**How ClearFills enforces this:**
- **Server-side UTC clock:** All TTL expirations, daily loss window rollovers, and audit timestamps are generated inside the firewall process using `datetime.now(timezone.utc)`. Caller timestamps are ignored for policy evaluation.
- **Trusted `PortfolioProvider`:** In `clearfills_desk` and hosted MCP execution, the firewall reads account equity, open positions, and live quotes directly from the broker adapter (IBKR Gateway snapshot) rather than trusting numbers passed in tool arguments.
- **Fresh-quote slippage guard:** Before dispatching an approved order, `clearfills watch` fetches a fresh quote from IB Gateway and aborts if execution price has drifted beyond the configured slippage guard (default 50 bps).

---

## 3. Dual-Key Split Trust & Hardware Passkey Co-Signing

### Policy Authority vs. Execution Worker
ClearFills separates signing from execution:
- **Policy Authority (Signer):** Evaluates risk rules and holds the Ed25519 private key (`authority_ed25519.pem`). It signs an RFC 8785 (JCS) canonical hash of the exact order parameters (`canonical_order_hash`) with a single-use nonce and 120-second TTL.
- **Execution Worker (`clearfills watch`):** Holds only the **verify-only Ed25519 public key**. Before routing any order to IBKR, it verifies the Ed25519 signature, checks TTL and nonce replay protection, and enforces `CLEARFILLS_ALLOW_LIVE=1` + `ibkr.allow_live: true`.

Compromising the worker alone does not grant the Ed25519 signing key; compromising the policy authority alone cannot dispatch orders if the worker requires a human passkey co-signature.

### Pinned Hardware WebAuthn Passkey Co-Sign
When `CLEARFILLS_REQUIRE_PASSKEY_COSIGN=1` is enabled on the worker (the default in `deploy/isolated-worker/`), every order requires a WebAuthn assertion verified locally by the worker against a pinned public key:
- Strict `rpIdHash` verification (prevents cross-domain phishing assertions).
- Strict `origin` verification.
- User Verification (`UV`) flag enforcement (`CLEARFILLS_REQUIRE_PASSKEY_UV=1`, requiring biometric or hardware PIN).
- Nonce-bound challenge derived from the RFC 8785 canonical order hash so an assertion cannot be replayed on a different symbol, quantity, or price.

### Honest Disclosure: Platform Authenticators vs. Hardware Wallets
Platform passkeys (macOS Touch ID, Windows Hello, iCloud Keychain) **do not have an isolated hardware screen** like a Ledger or Trezor. If your browser or desktop OS is compromised, malware could display "Buy 10 SGOV" in the approval UI while prompting Touch ID to sign a different canonical hash.

**Mitigation:** Enable out-of-band confirmation echoes (Telegram or SMS alerts in ClearFills Cloud) so the server independently sends the exact symbol, side, quantity, limit price, and short order hash to a separate device before you complete the biometric tap.

---

## 4. Ledger Integrity & Tail Truncation

Every decision (`PROPOSAL_APPROVED`, `PROPOSAL_VETOED`, `DISPATCH_ALLOWED`, `DISPATCH_REJECTED`, `KILL_SWITCH_TRIPPED`) is appended to an audit ledger where each entry is:
1. Linked to the previous entry via a SHA-256 hash chain (`GENESIS_HASH` -> entry N).
2. Signed with the authority's Ed25519 key so individual historical records cannot be modified silently.

**Known limitation (tail truncation / rollback):**
A local append-only file cannot prevent an attacker with filesystem write access from truncating the last `k` lines or restoring an earlier backup of the entire ledger file. The truncated prefix still passes local hash-chain verification.

**Mitigations:**
- **Filesystem isolation:** Keep the ledger inside the `clearfills_state` Docker volume (`deploy/isolated-worker/`) or under a dedicated OS user so the coding agent has no write access.
- **External checkpoint anchoring:** Periodically anchor the latest `(sequence_number, entry_hash, signature)` to an external append-only store (ClearFills Cloud checkpoint log, S3 Object Lock, or a remote syslog/WORM host) so any local truncation is immediately detectable during reconciliation.

---

## Threat Summary Matrix

| Threat | Attacker Capability | Defense in ClearFills | Residual Risk |
| :--- | :--- | :--- | :--- |
| Prompt-injected trade sizing / missing stop | Controls LLM tool arguments | Deterministic sleeve rules, hard stop-loss requirement, notional caps | Misconfigured `.clearfills.yaml` rules |
| Spoofed NAV or timestamps | Controls MCP / SDK call payload | Server-side UTC clock + trusted `PortfolioProvider` broker snapshot | Broker API returning stale delayed data |
| Attestation replay or tampering | Intercepts or replays signed JSON | RFC 8785 JCS hash, 120s TTL, single-use nonce tracking | None within TTL/nonce window if state persists |
| Same-UID coding agent theft | Shell access as same OS user | `deploy/isolated-worker/` (UID 10001 Docker volume) or Unix-socket separate user | High if operator ignores isolation and runs same-UID |
| Rogue Cloud / compromised Inbox | Controls ClearFills Cloud API | Local worker verifies pinned WebAuthn Passkey (`rpIdHash`, `origin`, `UV`, order hash) | Compromised operator desktop/browser (no hardware screen on Touch ID); mitigated by out-of-band Telegram/SMS echo |
| Audit log tampering / tail truncation | Write access to local state dir | SHA-256 hash chain + Ed25519 signed entries + external checkpoint anchoring | Local truncation undetectable without external checkpoint |
| Accidental live execution | Config typo or agent calling live port | Dual opt-in (`ibkr.allow_live: true` AND `CLEARFILLS_ALLOW_LIVE=1`), port 4002 paper default | Operator intentionally sets both flags in paper script |

---

## Reporting Vulnerabilities

See [`SECURITY.md`](SECURITY.md) for responsible disclosure contacts, scope, and response timelines.
