# ClearFills

[![License](https://img.shields.io/badge/License-Apache_2.0-10B981.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![PyPI](https://img.shields.io/pypi/v/clearfills-firewall.svg)](https://pypi.org/project/clearfills-firewall/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Website](https://img.shields.io/badge/site-clearfills.com-090B10.svg)](https://clearfills.com)

**Give AI a seat at your portfolio — without giving it your broker password.**

ClearFills is an open-core **Agentic Wealth & Execution OS**. Connect any frontier agent you already pay for (Claude Code, Codex, Cursor, Windsurf, OpenClaw) via MCP to unify Personal + Corporate net worth across banks and brokerages, enforce deterministic Ed25519 pre-trade risk rules, run scheduled standing mandates, and execute safely on 1-tap human approval.

- **Web Console (`Portfolio · Inbox · Rules · Lab`):** [https://clearfills.com/console](https://clearfills.com/console) *(60-second sandbox demo, $0)*
- **Hosted Remote MCP (zero install):** `https://clearfills-api.fly.dev/mcp`
- **Quickstart & Architecture:** [docs/QUICKSTART.md](docs/QUICKSTART.md)
- **Machine-Readable Docs:** [llms.txt](https://clearfills.com/llms.txt) · [agents.txt](https://clearfills.com/agents.txt)

---

## How It Works

```text
Claude / Codex / Cursor / Standing Mandates
                 │  (MCP — zero broker passwords)
                 ▼
      ClearFills Cloud & Risk Firewall
   ┌─────────────────────────────────────┐
   │ • Multi-Entity Net Worth (BoC FX)   │
   │ • Per-Sleeve Ed25519 Policy Engine  │
   │ • 1-Tap Human Approval Inbox        │
   └──────────────────┬──────────────────┘
                      │  (human clicks Approve)
                      ▼
       clearfills-desk watch (local)
   ┌─────────────────────────────────────┐
   │ • Atomic claim + 50 bps guard       │
   │ • Fresh Ed25519 re-attestation      │
   │ • IBKR Gateway (loopback/Tailscale) │
   └─────────────────────────────────────┘
```

---

## 60-Second Quickstart

### 1. Try the Hosted Console & Sandbox (`$0`)
1. Sign in at [clearfills.com/console](https://clearfills.com/console) (GitHub or Google).
2. Click **Launch 60-Second Sandbox Demo** on `Portfolio` to seed a sample $1.2M Personal + Corporate balance sheet and queue an `SGOV` sweep.
3. Open `Inbox` and tap **Approve & Execute** to see an instant Ed25519-signed receipt and verified track record. Click **Clear Sandbox Data** anytime to connect real accounts.

### 2. Connect Your AI Agent (No `pip install` Required)
Paste your API key from **Rules → API Keys** into Claude Code, Codex, or Cursor using the hosted Streamable-HTTP MCP endpoint (`https://clearfills-api.fly.dev/mcp`):

```json
{
  "mcpServers": {
    "clearfills": {
      "type": "http",
      "url": "https://clearfills-api.fly.dev/mcp",
      "headers": {
        "Authorization": "Bearer cf_sk_..."
      }
    }
  }
}
```

Or run the local Python MCP server (`pip install clearfills-firewall`):
```bash
# Offline local firewall MCP
claude mcp add clearfills -- uvx --from clearfills-firewall clearfills-firewall-mcp

# Cloud Trading OS MCP over stdio
CLEARFILLS_API_KEY="cf_sk_..." \
  claude mcp add clearfills -- uvx --from clearfills-firewall clearfills-firewall-mcp --cloud
```

### 3. Connect Live or Paper IBKR (`packages/clearfills-desk`)
```bash
# Validate fail-closed config (Paper: port 4002 + DU* | Live: port 4001 + two-key opt-in)
CLEARFILLS_ALLOW_LIVE=1 clearfills-desk validate --config desk.live.yaml

# Run the local execution daemon for 1-tap Inbox approvals (add --dry-run to test safely)
CLEARFILLS_ALLOW_LIVE=1 CLEARFILLS_API_KEY="cf_sk_..." \
  clearfills-desk watch --config desk.live.yaml --dry-run
```

---

## Per-Sleeve Deterministic Risk Firewall

Zero LLM in the approval path. Every `TradeProposal` is routed to a sleeve and evaluated deterministically before a single-use Ed25519 attestation (120s TTL) is signed:

| Sleeve | Example Symbols | Stop-Loss | Max Notional | Global Kill-Switch & Daily Loss |
| :--- | :--- | :--- | :--- | :--- |
| `cash_equivalent` | `SGOV`, `BIL`, `CBIL`, `SHV` | Exempt | $500,000 | Fail-closed enforced |
| `core_index` | `VT`, `VTI`, `VOO`, `SPY`, `VEQT` | Exempt | $500,000 | Fail-closed enforced |
| `active_trading` | All other equities / swing | **Required** | $50,000 | Fail-closed enforced |

Every decision (`APPROVED`, `VETO`, `NONCE_ALREADY_SPENT`, `KILL_SWITCH_TRIPPED`) appends to a **SHA-256 hash-chained audit ledger**.

---

## Repository Layout

- [`packages/risk-firewall`](packages/risk-firewall/) — Apache-2.0 `clearfills-firewall` (`v0.4.0` on PyPI): deterministic policy engine, per-sleeve rules, Ed25519 attestation authority, SHA-256 audit ledger, MCP stdio & FastAPI server.
- [`packages/clearfills-desk`](packages/clearfills-desk/) — Apache-2.0 `clearfills-desk`: IBKR execution adapter (`whatIf` previews, delayed-quote metadata, multi-agent `clientId` retry), `clearfills-desk-mcp`, `clearfills-desk sync`, and `clearfills-desk watch`.
- [`docs/QUICKSTART.md`](docs/QUICKSTART.md) — Concise operator guide covering Portfolio, Inbox, Rules, Lab, and live IBKR setup.

---

## Security & Non-Custodial Guarantee

- **Zero credential custody:** AI agents never receive brokerage or banking passwords.
- **Fail-closed live execution:** Live IBKR requires both `ibkr.allow_live: true` in config and `CLEARFILLS_ALLOW_LIVE=1` in the execution environment, loopback/Tailscale-only transport, and a 50 bps fresh-quote slippage guard on `clearfills-desk watch`.
- **Software only:** ClearFills is self-directed risk engineering and execution software — not an investment advisor, custodian, or broker-dealer.
