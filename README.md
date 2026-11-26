# ClearFills

<!-- mcp-name: com.clearfills/clearfills -->

[![License](https://img.shields.io/badge/License-Apache_2.0-10B981.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![PyPI](https://img.shields.io/pypi/v/clearfills.svg)](https://pypi.org/project/clearfills/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Glama MCP Server](https://glama.ai/mcp/servers/clearfills/clearfills/badge)](https://glama.ai/mcp/servers/clearfills/clearfills)

**Deterministic pre-trade risk firewall, cryptographic order attestation, and isolated broker execution guard for AI trading agents.**

ClearFills sits between untrusted LLM trading agents (Claude, Claude Code, Cursor, Codex, `TradingAgents`, `ai-hedge-fund`) and your brokerage execution gateway (Interactive Brokers Gateway). Agents never receive broker credentials and cannot execute orders without passing deterministic math checks, single-use split-key Ed25519 ticket verification, and optional hardware WebAuthn passkey co-signing.

- **Threat Model & Disclosure:** [`EXECUTION_THREAT_MODEL.md`](EXECUTION_THREAT_MODEL.md) · [`SECURITY.md`](SECURITY.md)
- **Isolated Docker Worker (UID 10001):** [`deploy/isolated-worker/`](deploy/isolated-worker/)
- **Install:** `pip install clearfills` (add `pip install 'clearfills[ibkr]'` for IBKR Gateway execution)
- **Docs:** [`docs/QUICKSTART.md`](docs/QUICKSTART.md) · [`docs/AGENT_INTEGRATION.md`](docs/AGENT_INTEGRATION.md) · [clearfills.com/docs](https://clearfills.com/docs)
- **Hosted Sandbox ($0) & Remote MCP:** [clearfills.com/console](https://clearfills.com/console) · `https://clearfills-api.fly.dev/mcp`

---

## Architecture & Split-Key Trust Model

ClearFills assumes the AI agent proposing trades is **untrusted** (susceptible to prompt injection, hallucinated sizing, or tool misuse) and separates policy signing from order dispatch:

```text
+----------------------------------+        +----------------------------------------+
|  UNTRUSTED ZONE                  |        |  ISOLATED TRUST ZONE                   |
|  AI Coding Agent / LLM Runtime   |        |  UID 10001 Docker / Separate OS User   |
|  (Claude, Codex, Cursor, SDK)    |        |                                        |
|                                  |  MCP/  |  1. Policy Authority (Signer)          |
|  - Can be prompt-injected        +------->+     - Zero-LLM deterministic policy    |
|  - Never holds broker passwords  |  HTTP  |     - Server UTC clock + broker state  |
|  - Cannot forge Ed25519 tickets  |        |     - RFC 8785 JCS + Ed25519 private   |
+----------------------------------+        |                                        |
                                            |  2. Execution Worker (clearfills watch)|
                                            |     - Verify-only Ed25519 public key   |
                                            |     - py_webauthn + monotonic signCount|
                                            |     - 50 bps fresh-quote slippage guard|
                                            +-------------------+--------------------+
                                                                |
                                                                v (loopback / Tailscale)
                                            +----------------------------------------+
                                            |  IBKR Gateway (4002 paper / 4001 live) |
                                            +----------------------------------------+
```

---

## Core Security Primitives

1. **Deterministic Zero-LLM Policy Engine (`clearfills_firewall`)**
   Every `TradeProposal` is evaluated with pure Python math against per-sleeve notional caps, mandatory limit prices and protective stop-losses, per-trade risk and total portfolio heat caps, anti-salami-slicing cumulative daily notional caps, and a sliding 60-second order rate limit. Caller-supplied timestamps are ignored in favor of the server UTC clock, and `clearfills_desk` pulls account equity and open positions directly from a trusted `PortfolioProvider` (IBKR snapshot) rather than trusting LLM tool arguments.

2. **RFC 8785 (JCS) Canonical Hashing & Split-Key Ed25519 Tickets**
   Immutable order legs (symbol, side, order type, normalized quantity, limit/stop/target prices, venue, proposal ID) are serialized via RFC 8785 JSON Canonicalization Scheme (`canonical.py`) and hashed with SHA-256 into `canonical_order_hash`. `AttestationAuthority` signs a single-use, 120-second TTL Ed25519 ticket; the execution worker (`SplitKeyTicketVerifier` / `AttestationVerifier`) holds **only the verify-only Ed25519 public key** and persists spent nonces atomically (`spent_ticket_nonces.json`) to block replay and parameter tampering.

3. **Hardware Passkey Co-Signing (`py_webauthn` + Monotonic `signCount`)**
   When `CLEARFILLS_REQUIRE_PASSKEY_COSIGN=1` is enabled (the default in [`deploy/isolated-worker/`](deploy/isolated-worker/)), `webauthn_verifier.py` delegates assertion verification to `py_webauthn` against locally pinned SPKI public keys (never trusting public keys carried in the assertion payload). It strictly enforces `rpIdHash`, `origin`, User Present (`UP`) and User Verified (`UV`) flags, a nonce-bound challenge (`base64url(sha256(f"{nonce}:{canonical_order_hash}"))`), and monotonic `signCount` tracking to detect cloned authenticators or counter rollbacks.

4. **Mark-to-Market Latching Kill-Switch & Hash-Chained Audit Ledger**
   `KillSwitch` (`killswitch.py`) is backed by an atomic-write (`os.replace`) JSON state file and **fails closed** whenever the state file is missing, unreadable, or corrupt. Breaching the daily mark-to-market loss limit (`max_daily_loss_pct`) or a strategy envelope's peak-to-trough rolling drawdown (`max_drawdown_pct`) latches trading halted until an explicit operator reset with actor and reason. Every decision (`PROPOSAL_APPROVED`, `PROPOSAL_VETOED`, `DISPATCH_ALLOWED`, `DISPATCH_REJECTED`, `KILL_SWITCH_TRIPPED`) appends to a SHA-256 hash-chained, Ed25519-signed audit ledger (`ledger.py`).

5. **Separate-UID Docker Isolation (`deploy/isolated-worker/`)**
   Running an AI coding agent with shell access under the same OS user as `~/.clearfills/` gives that agent read/write access to signing keys and `killswitch.json` (documented in [`EXECUTION_THREAT_MODEL.md`](EXECUTION_THREAT_MODEL.md)). [`deploy/isolated-worker/`](deploy/isolated-worker/) runs `clearfills watch` as non-root UID `10001` (`clearfills:clearfills`) with `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, a named Docker volume (`clearfills_state`, `0700` dir / `0600` files), passkey co-signing ON by default, and live execution OFF by default. For non-Docker deployments, `enclave_client.py` supports separating the signer over a permissioned `AF_UNIX` socket.

---

## Install & 30-Second Local Verification

```bash
# Core firewall, Python SDK, stdio MCP server, and CLI (zero broker libs)
pip install clearfills

# With IBKR Gateway execution (watch / sync ibkr / mcp --ibkr)
pip install 'clearfills[ibkr]'

# With local FastAPI HTTP firewall server (`clearfills serve`)
pip install 'clearfills[server]'
```

Verify the firewall, policy vetoes, and single-use replay protection 100% offline with zero broker credentials:

```bash
# 3-step adversarial check (rogue market order, missing stop-loss, attestation replay)
clearfills redteam --local

# 25-scenario adversarial safety benchmark against local FirewallService
clearfills benchmark
```

### Python SDK

```python
from clearfills import FirewallService, PortfolioSnapshot, RiskPolicy, TradeProposal
```

### Paper & Live IBKR Setup

Live IBKR execution is **fail-closed**: it requires both `ibkr.allow_live: true` in `.clearfills.yaml` and `CLEARFILLS_ALLOW_LIVE=1` in the execution environment, loopback or Tailscale-only transport, and a 50 bps fresh-quote slippage guard on `clearfills watch`.

```bash
# 1. Generate a paper config (defaults: port 4002, DU* paper account, allow_live: false)
clearfills init --mode paper

# 2. Run 6 diagnostic checks (Python, config, IBKR extra, IB Gateway TCP, Cloud auth, SHA-256 audit)
clearfills doctor

# 3. Validate fail-closed config before running the worker
clearfills validate --config .clearfills.yaml

# 4. Run the isolated Docker worker (recommended for live capital)
docker compose -f deploy/isolated-worker/docker-compose.isolated.yml up -d --build
```

---

## CLI Reference (12 Subcommands)

| Command | Purpose |
| :--- | :--- |
| `clearfills init` | Generate a commented `.clearfills.yaml` with paper defaults (`port 4002`, `allow_live: false`) and per-sleeve caps. |
| `clearfills doctor` | Run 6 environment diagnostics: Python version, config validity, IBKR extra, IB Gateway TCP, Cloud auth, and SHA-256 ledger integrity. |
| `clearfills mcp` | Start the local stdio MCP server (`clearfills_firewall` by default; pass `--ibkr` to enable IBKR execution tools). |
| `clearfills watch` | Local execution worker: claims approved orders, verifies Ed25519 ticket + optional `py_webauthn` passkey, checks 50 bps slippage guard, and routes to IBKR (`--dry-run` supported). |
| `clearfills sync` | Sync read-only balances and positions from IBKR, EVM wallets, or a local snapshot to ClearFills Cloud. |
| `clearfills validate` | Validate `.clearfills.yaml` and enforce fail-closed paper/live IBKR safety gates (`allow_live` + `CLEARFILLS_ALLOW_LIVE=1`). |
| `clearfills redteam` | Run a 3-step live or `--local` offline firewall test (rogue market order, missing stop-loss, attestation replay). |
| `clearfills benchmark` | Run the 25-scenario adversarial safety benchmark against the local `FirewallService` (`--json` supported). |
| `clearfills compile-policy` | Deterministically compile plain-English risk rules into a verified `RiskPolicy` YAML (`--output`, `--json`). |
| `clearfills serve` | Start the local FastAPI HTTP firewall server on `127.0.0.1:8080` (requires `clearfills[server]`). |
| `clearfills prove` | Generate a TLSNotary MPC-TLS fill proof (`.presentation.tlsn`) or byte-range redaction plan (`--plan-only`) for a broker fill. |
| `clearfills verify-proof` | Verify a TLSNotary (`.presentation.tlsn`) or Ed25519 notary JSON fill proof against a pinned notary public key. |

---

## Per-Sleeve Default Risk Policy

Every `TradeProposal` is routed to a sleeve and evaluated deterministically before a single-use 120-second Ed25519 ticket is issued:

| Sleeve | Example Symbols | Stop-Loss | Max Notional | Global Kill-Switch & Daily Loss |
| :--- | :--- | :--- | :--- | :--- |
| `cash_equivalent` | `SGOV`, `BIL`, `CBIL`, `SHV` | Exempt | $500,000 | Fail-closed enforced |
| `core_index` | `VT`, `VTI`, `VOO`, `SPY`, `VEQT` | Exempt | $500,000 | Fail-closed enforced |
| `active_trading` | All other equities / swing | **Required** | $50,000 | Fail-closed enforced |

---

## MCP Setup & Runnable Examples

Connect Claude Code, Cursor, or Codex to either the local offline stdio MCP server or the hosted remote MCP endpoint (OAuth 2.1 / Bearer):

```bash
# Local offline firewall MCP via uvx (zero cloud dependency)
claude mcp add clearfills -- uvx clearfills mcp

# Hosted Remote MCP (OAuth 2.1 + Bearer)
claude mcp add --transport http clearfills https://clearfills-api.fly.dev/mcp \
  --header "Authorization: Bearer cf_sk_..."
```

| Example | What It Demonstrates |
| :--- | :--- |
| [`examples/tradingagents_safe_execution.py`](examples/tradingagents_safe_execution.py) | Wrap `TauricResearch/TradingAgents` output with `FirewallService`, enforce limit orders + hard stops, mint a 120s Ed25519 attestation, and test single-use replay rejection. |
| [`examples/ai_hedge_fund_safe_execution.py`](examples/ai_hedge_fund_safe_execution.py) | Route `virattt/ai-hedge-fund` portfolio decisions through per-sleeve risk rules (`active_trading` vs. `cash_equivalent`) with optional approval-queue dispatch. |
| [`examples/claude_mcp_setup.md`](examples/claude_mcp_setup.md) | Copy-paste MCP configuration for Claude.ai, Claude Code, Cursor, and Codex CLI. |

```bash
pip install clearfills
python examples/tradingagents_safe_execution.py
python examples/ai_hedge_fund_safe_execution.py
```

---

## Open Core (Apache-2.0) vs. ClearFills Cloud

| Capability | Open Core (Apache-2.0, this repo) | ClearFills Cloud (`clearfills.com`) |
| :--- | :--- | :--- |
| **Deterministic Risk Firewall (`clearfills_firewall`)** | Full policy engine, per-sleeve caps, hard stop-losses, latching kill-switch, SHA-256 + Ed25519 audit ledger | Hosted evaluation and policy sync |
| **Cryptography & Canonicalization** | RFC 8785 (JCS) order hashing, split-key Ed25519 signer (`AttestationAuthority`) and verify-only verifier (`SplitKeyTicketVerifier`) | Managed policy authority and key rotation |
| **Hardware Passkey Co-Sign Verifier** | Local `py_webauthn` verifier (`rpIdHash`, `origin`, `UP` + `UV`, nonce-bound order hash, monotonic `signCount`) | Browser and mobile 1-Tap Passkey Inbox UI |
| **Strategy Envelopes** | Deterministic drawdown auto-kill and runaway-loop throttling | Visual envelope builder and live monitoring |
| **Local IBKR Execution (`clearfills_desk`)** | `clearfills watch`, `clearfills sync`, `whatIf` previews, 50 bps slippage guard, `enclave_client` (`AF_UNIX`) | Cloud approval queue and worker heartbeats |
| **MCP & HTTP Servers** | Local stdio MCP (`clearfills mcp`) and FastAPI server (`clearfills serve`) | Hosted Remote MCP (`OAuth 2.1` + Bearer) |
| **Separate-User Isolation Kit** | [`deploy/isolated-worker/`](deploy/isolated-worker/) (UID 10001 Docker + `clearfills_state` volume) | Remote checkpoint anchoring and isolated enclaves |
| **Multi-Entity Portfolio Console** | Local YAML / CLI | Hosted Personal, Corporate, Trust, TFSA/RRSP console |
| **Additional Broker Adapters** | IBKR Gateway (local) | Hosted Alpaca execution and SnapTrade read-only aggregation |
| **Out-of-Band Approval Echoes** | Local logs | Telegram and SMS confirmation echoes with short order hash |
| **Tax, Entity & Filing Engines** | Not included | Cross-border tax, CCPC, FX, and SEC EDGAR analysis engines |

---

## Repository Layout

- [`src/clearfills/`](src/clearfills/): Unified `clearfills` Python package and 12-command CLI.
- [`packages/risk-firewall/`](packages/risk-firewall/): Apache-2.0 `clearfills_firewall`: deterministic policy engine, per-sleeve rules, RFC 8785 JCS canonicalization (`canonical.py`), Ed25519 attestation authority (`attestation.py`), fail-closed `KillSwitch` (`killswitch.py`), `StrategyEnvelope` (`envelopes.py`), SHA-256 + Ed25519 audit ledger (`ledger.py`), stdio MCP and FastAPI server.
- [`packages/clearfills-desk/`](packages/clearfills-desk/): Apache-2.0 `clearfills_desk`: `SplitKeyTicketVerifier` (`runtime.py`), `py_webauthn` passkey verifier with monotonic `signCount` (`webauthn_verifier.py`), IBKR execution adapter (`ibkr.py`), `AF_UNIX` signer client (`enclave_client.py`), `clearfills watch`, and `clearfills sync`.
- [`deploy/isolated-worker/`](deploy/isolated-worker/): Hardened Docker isolation kit (UID `10001`, read-only rootfs, `cap_drop: [ALL]`, `0600` named volume, passkey co-sign enabled by default).
- [`examples/`](examples/): Runnable integration examples for `TradingAgents`, `ai-hedge-fund`, Claude, Cursor, and Codex.
- [`EXECUTION_THREAT_MODEL.md`](EXECUTION_THREAT_MODEL.md) & [`SECURITY.md`](SECURITY.md): Security boundaries, same-UID host risks, known limitations (tail truncation, platform passkey screen trust), and responsible disclosure policy.

---

## Security Status & Scope

- **Beta & audit status:** `v0.8.x Public Beta`. Paper-first (`port 4002`, `DU*` account, `--dry-run`) is recommended before connecting live capital. No third-party security audit has been completed yet; independent code reviews and red-team reports are welcome via [GitHub Security Advisories](https://github.com/clearfills/clearfills/security/advisories/new) or `security@clearfills.com` (see [`SECURITY.md`](SECURITY.md)).
- **Threat model:** Read [`EXECUTION_THREAT_MODEL.md`](EXECUTION_THREAT_MODEL.md) before deploying with live funds, especially the sections on same-UID coding-agent isolation and ledger tail truncation.
- **Software only:** ClearFills is self-directed risk engineering and execution software, not an investment advisor, custodian, or broker-dealer.
