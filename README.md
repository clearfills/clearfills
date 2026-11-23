# ClearFills Pre-Trade Risk Firewall (`clearfills-firewall`)

[![License](https://img.shields.io/badge/License-Apache_2.0-10B981.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Website](https://img.shields.io/badge/site-clearfills.com-090B10.svg)](https://clearfills.com)

**Deterministic Ed25519 pre-trade risk firewall & MCP server for AI trading agents.**

Sits between any untrusted AI trading agent (Claude, Grok, Codex, `TradingAgents`, `ai-hedge-fund`, or custom Python loops) and your execution gateway so LLMs **never hold brokerage API keys** and can never hallucinate or get prompt-injected into an unbounded market sweep.

- **Interactive Simulator & Live Arena:** [https://clearfills.com](https://clearfills.com)
- **LLM Overview:** [https://clearfills.com/llms.txt](https://clearfills.com/llms.txt)
- **Agent Operational Contract:** [https://clearfills.com/agents.txt](https://clearfills.com/agents.txt)

---

## Install

```bash
pip install clearfills-firewall
```

Run the MCP stdio server:
```bash
clearfills-firewall-mcp
# or: uvx --from clearfills-firewall clearfills-firewall-mcp
```

Run the FastAPI HTTP firewall service:
```bash
clearfills-firewall
```

---

## Connect to Claude Code & Cursor

### Claude Code
```bash
claude mcp add clearfills -- uvx --from clearfills-firewall clearfills-firewall-mcp
```

### Cursor (`.cursor/mcp.json`) / Project `.mcp.json`
```json
{
  "mcpServers": {
    "clearfills": {
      "command": "uvx",
      "args": ["--from", "clearfills-firewall", "clearfills-firewall-mcp"]
    }
  }
}
```

---

## Deterministic Policy Invariants (Zero LLM in the Loop)

Every `TradeProposal` must satisfy all deterministic math rules before an Ed25519 attestation is signed:

| Rejection Code | Invariant Enforced |
| :--- | :--- |
| `MARKET_ORDER_FORBIDDEN` | Strict `LMT` (limit) orders only — `MKT` sweeps are unconditionally vetoed |
| `MISSING_HARD_STOP` | Atomic bracket stop-loss required (or bounded binary collateral on Polymarket/Kalshi) |
| `MAX_TRADE_RISK_EXCEEDED` | <= 1.5% NLV per equity trade / <= 1.0% fractional Kelly cap on binary markets |
| `MAX_POSITION_NOTIONAL_EXCEEDED` | <= 20% gross NLV concentration cap |
| `DAILY_DRAWDOWN_KILLSWITCH` | Fail-closed intraday halt at -3.0% PnL |
| `NONCE_ALREADY_SPENT` | Single-use 120-second Ed25519 attestation nonce; replays rejected and logged |

Every `APPROVED`, `VETO`, and `VETO (REPLAY)` decision appends to a **SHA-256 hash-chained audit ledger** (`prev_hash -> entry_hash`).

---

## Drop-In Shims for Open-Source Trading Agents

Wrap `TauricResearch/TradingAgents` or `virattt/ai-hedge-fund` without rewriting their research pipelines:

```python
from clearfills_firewall import FirewallService
from clearfills_firewall.shims import TradingAgentsShim, AIHedgeFundShim
```

---

## Open Core vs. Pro Infrastructure Kit

- **Open Core (`clearfills-firewall`, Apache-2.0 — $0):** Deterministic risk engine, Ed25519 120s TTL attestation authority, replay protection, kill-switch, SHA-256 audit ledger, MCP stdio server, FastAPI server, and `TradingAgents` / `ai-hedge-fund` shims.
- **Pro Infrastructure Kit ($299 one-time):** Turnkey private source repo with Fly.io + Tailscale private mesh, headless IB Gateway + IBC + API-handshake watchdog, attested-only IBKR / Alpaca / Polymarket CLOB / Kalshi adapters, and Web Console → [clearfills.com/#pricing](https://clearfills.com/#pricing).
- **Private Desk Install (MLDSAI Inc., $15k–$25k):** Custom deployment for family offices and prop desks → [Book 30-min call](https://cal.com/richard-abrich/30min).

*Risk engineering and execution software only. Not investment advice.*
