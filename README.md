# ClearFills

[![License](https://img.shields.io/badge/License-Apache_2.0-10B981.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![PyPI](https://img.shields.io/pypi/v/clearfills.svg)](https://pypi.org/project/clearfills/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Website](https://img.shields.io/badge/site-clearfills.com-090B10.svg)](https://clearfills.com)
[![Glama MCP Server](https://glama.ai/mcp/servers/clearfills/clearfills/badge)](https://glama.ai/mcp/servers/clearfills/clearfills)

**Let AI manage your portfolio. Never give it your broker password.**

ClearFills is an open-core execution firewall and MCP server for AI trading agents. Connect Claude, Claude Code, Cursor, Codex, `TradingAgents`, or `ai-hedge-fund` to Interactive Brokers (IBKR), Alpaca, and multi-account portfolios with deterministic Ed25519 pre-trade risk rules and 1-tap human approval.

- **Install:** `pip install clearfills` (add `pip install 'clearfills[ibkr]'` for IBKR Gateway execution)
- **Live Sandbox ($0, 60 seconds):** [https://clearfills.com/console](https://clearfills.com/console)
- **Hosted Remote MCP (OAuth 2.1 + Bearer):** `https://clearfills-api.fly.dev/mcp`
- **Documentation:** [clearfills.com/docs](https://clearfills.com/docs) · [docs/QUICKSTART.md](docs/QUICKSTART.md) · [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md)
- **Machine-Readable Docs:** [llms.txt](https://clearfills.com/llms.txt) · [agents.txt](https://clearfills.com/agents.txt)

---

## Install & Unified CLI

```bash
# Core firewall, Python SDK, MCP server, and CLI (zero broker libs)
pip install clearfills

# With IBKR Gateway execution (watch / sync ibkr / mcp --ibkr)
pip install 'clearfills[ibkr]'

# With local FastAPI HTTP firewall server (`clearfills serve`)
pip install 'clearfills[server]'
```

Run the unified `clearfills` CLI right from your terminal:

```bash
# 1. Verify the firewall in 3 seconds (rogue market order, missing stop, single-use replay)
clearfills redteam --local

# 2. Generate a safe, commented .clearfills.yaml (paper defaults + per-sleeve caps)
clearfills init

# 3. Run 6 diagnostic checks (Python, config, IBKR extra, IB Gateway TCP, Cloud auth, SHA-256 audit)
clearfills doctor

# 4. Run the local stdio MCP server (or add --ibkr for IBKR execution tools)
clearfills mcp

# 5. Watch ClearFills Cloud for 1-Tap Inbox approvals (add --dry-run to test safely)
CLEARFILLS_API_KEY="cf_sk_..." clearfills watch --dry-run
```

---

## How It Works (3 Steps)

1. **Connect read-only:** Sync your balances and holdings from IBKR, SnapTrade, EVM wallets, or statements without handing brokerage passwords to an LLM.
2. **Enforce hard math:** Every AI trade proposal passes through a deterministic, zero-LLM risk firewall (`clearfills`) that enforces per-sleeve notional caps, mandatory stop-losses, daily loss limits, and a fail-closed kill-switch before minting a single-use 120-second Ed25519 attestation.
3. **Approve in one tap:** Review attested orders in your ClearFills Inbox and tap **Approve**. Your local `clearfills watch` worker atomically claims the order, checks a fresh live quote (50 bps slippage guard), re-attests, and routes to IBKR or Alpaca.

```text
Claude / Codex / Cursor / TradingAgents / ai-hedge-fund
                 |  (MCP or Python SDK, zero broker passwords)
                 v
      ClearFills Cloud & Risk Firewall
   +-------------------------------------+
   | 1. Connect read-only (multi-entity) |
   | 2. Enforce hard math (Ed25519)      |
   | 3. Approve in one tap (Inbox)       |
   +------------------+------------------+
                      |  (human clicks Approve)
                      v
           clearfills watch (local)
   +-------------------------------------+
   | * Atomic claim + 50 bps guard       |
   | * Fresh Ed25519 re-attestation      |
   | * IBKR Gateway (loopback/Tailscale) |
   +-------------------------------------+
```

---

## 60-Second Quickstart

### 1. Try the Live Sandbox ($0)
1. Sign in at [clearfills.com/console](https://clearfills.com/console) (GitHub or Google).
2. Click **Launch 60-Second Sandbox Demo** on `Portfolio` to load a sample Personal + Corporate balance sheet and queue an `SGOV` T-bill sweep.
3. Open `Inbox` and tap **Approve & Execute** to inspect an Ed25519-signed execution receipt and SHA-256 audit trail. Click **Clear Sandbox Data** anytime to connect real accounts.

### 2. Connect Your AI Agent via MCP (No `pip install` Required)
Connect **Claude.ai** (OAuth 2.1), **Claude Code**, **Cursor**, or **Codex** to `https://clearfills-api.fly.dev/mcp`. See the full copy-paste guide in [`examples/claude_mcp_setup.md`](examples/claude_mcp_setup.md).

```bash
# Claude Code (Hosted Remote MCP)
claude mcp add --transport http clearfills https://clearfills-api.fly.dev/mcp \
  --header "Authorization: Bearer cf_sk_..."

# Claude Code (Local offline firewall MCP via uvx)
claude mcp add clearfills -- uvx clearfills mcp
```

### 3. Python SDK
```python
from clearfills import FirewallService, PortfolioSnapshot, RiskPolicy, TradeProposal
```

### 4. Connect Live or Paper IBKR
```bash
# Generate paper or live config
clearfills init --mode paper

# Validate fail-closed config (Paper: port 4002 + DU* | Live: port 4001 + two-key opt-in)
CLEARFILLS_ALLOW_LIVE=1 clearfills validate --config .clearfills.yaml

# Run the local execution daemon for 1-tap Inbox approvals (add --dry-run to test safely)
CLEARFILLS_ALLOW_LIVE=1 CLEARFILLS_API_KEY="cf_sk_..." \
  clearfills watch --config .clearfills.yaml --dry-run
```

---

## Runnable Examples

| Example | What It Shows |
| :--- | :--- |
| [`examples/tradingagents_safe_execution.py`](examples/tradingagents_safe_execution.py) | Wrap `TauricResearch/TradingAgents` debate output with `FirewallService`, enforce limit orders + hard stops, issue a 120s Ed25519 attestation, and verify single-use replay protection. |
| [`examples/ai_hedge_fund_safe_execution.py`](examples/ai_hedge_fund_safe_execution.py) | Route `virattt/ai-hedge-fund` multi-analyst portfolio decisions through per-sleeve risk rules (`active_trading` vs. `cash_equivalent`) with optional ClearFills Cloud 1-Tap Approval Inbox queuing. |
| [`examples/claude_mcp_setup.md`](examples/claude_mcp_setup.md) | Copy-paste setup for Claude.ai (OAuth 2.1 Remote MCP), Claude Code (`claude mcp add`), Cursor, and OpenAI Codex CLI. |

Run any Python example locally with zero broker credentials:
```bash
pip install clearfills
python examples/tradingagents_safe_execution.py
python examples/ai_hedge_fund_safe_execution.py
```

---

## Per-Sleeve Deterministic Risk Firewall

Zero LLM in the approval path. Every `TradeProposal` is routed to a sleeve and evaluated deterministically before a single-use Ed25519 attestation (120s TTL) is signed:

| Sleeve | Example Symbols | Stop-Loss | Max Notional | Global Kill-Switch & Daily Loss |
| :--- | :--- | :--- | :--- | :--- |
| `cash_equivalent` | `SGOV`, `BIL`, `CBIL`, `SHV` | Exempt | $500,000 | Fail-closed enforced |
| `core_index` | `VT`, `VTI`, `VOO`, `SPY`, `VEQT` | Exempt | $500,000 | Fail-closed enforced |
| `active_trading` | All other equities / swing | **Required** | $50,000 | Fail-closed enforced |

Every decision (`PROPOSAL_APPROVED`, `PROPOSAL_VETOED`, `DISPATCH_ALLOWED`, `DISPATCH_REJECTED`, `KILL_SWITCH_TRIPPED`) appends to a **SHA-256 hash-chained audit ledger**.

---

## Repository Layout

- [`src/clearfills`](src/clearfills/): Unified `clearfills` Python package & CLI (`init`, `doctor`, `mcp`, `watch`, `sync`, `validate`, `redteam`, `serve`).
- [`packages/risk-firewall`](packages/risk-firewall/): Apache-2.0 `clearfills_firewall`, deterministic policy engine, per-sleeve rules, Ed25519 attestation authority, SHA-256 audit ledger, MCP stdio and FastAPI server.
- [`packages/clearfills-desk`](packages/clearfills-desk/): Apache-2.0 `clearfills_desk`, IBKR execution adapter (`whatIf` previews, delayed-quote metadata, multi-agent `clientId` retry), `clearfills-desk-mcp`, `clearfills sync`, and `clearfills watch`.
- [`examples/`](examples/): Runnable integration examples for `TradingAgents`, `ai-hedge-fund`, Claude, Cursor, and Codex.
- [`docs/QUICKSTART.md`](docs/QUICKSTART.md): Concise operator guide covering Portfolio, Inbox, Rules, Lab, and live IBKR setup.

---

## Security & Non-Custodial Guarantee

- **Zero credential custody:** AI agents never receive brokerage or banking passwords.
- **Fail-closed live execution:** Live IBKR requires both `ibkr.allow_live: true` in config and `CLEARFILLS_ALLOW_LIVE=1` in the execution environment, loopback/Tailscale-only transport, and a 50 bps fresh-quote slippage guard on `clearfills watch`.
- **Software only:** ClearFills is self-directed risk engineering and execution software, not an investment advisor, custodian, or broker-dealer.
