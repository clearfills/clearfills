# ClearFills Quickstart & Operator Guide

ClearFills is organized around **4 surfaces** matching how a human oversees autonomous agents:

| Surface | Route | Purpose |
| :--- | :--- | :--- |
| **Portfolio** | `/console/portfolio` | Unified Personal + Corporate net worth (live Bank of Canada FX), daily Net Worth Over Time chart, Entity/Custody/Deployment breakdown, and connected accounts. |
| **Inbox** | `/console/inbox` | 1-Tap Trade Approval Queue (with `Desk Worker: Online/Offline` status & optional Slack/Discord alerts) + immutable SHA-256 Execution Receipts. |
| **Rules** | `/console/rules` | Standing Mandates (scheduled treasury sweeps, concentration guards, tax-location audits), Per-Sleeve Guardrails & Kill-Switch, Remote MCP setup, and API Keys. |
| **Lab** | `/console/lab` | Strategy proving ground: Verified Cryptographic Track Record, Deflated Sharpe Ratio (DSR) Backtests, Watchlist, Research Notes, and Trade Journal. |

---

## 1. Try It in 60 Seconds (Zero Setup)

1. Sign in at [https://clearfills.com/console](https://clearfills.com/console) with GitHub or Google.
2. Click **Launch 60-Second Sandbox Demo** on `Portfolio`. This seeds a sample $1.2M Personal + Corporate balance sheet, activates a Corporate Treasury Sweep mandate, and queues an `SGOV` T-bill buy.
3. Open **Inbox** and click **Approve & Execute** — sandbox orders execute instantaneously with an Ed25519 receipt and update **Lab → Verified Proof**.
4. When ready to connect real accounts, click **Clear Sandbox Data** on `Portfolio`.

---

## 2. Connect Your AI Agent (Remote MCP — Zero Install)

Copy your API key from **Rules → API Keys** and add the hosted Streamable-HTTP MCP server (`https://clearfills-api.fly.dev/mcp`):

- **Supported today (Bearer auth):** Claude Code, Codex, Cursor, Windsurf.
- **Discovery endpoint:** `https://clearfills-api.fly.dev/.well-known/oauth-protected-resource`

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

Ask your agent:
> *"Check my Personal vs Corporate net worth in ClearFills, evaluate my standing mandates, and summarize any idle cash above my liquidity floor."*

---

## 3. Sync Banks & Brokerages

Open **Portfolio → + Connect Account**:
- **MetaMask / EVM Wallets:** 1-click browser wallet connect (Ethereum, Base, Arbitrum, Optimism, Polygon — read-only, zero private keys).
- **Questrade / Wealthsimple / SnapTrade:** Official OAuth read-only portfolio sync.
- **Interactive Brokers (IBKR):** Zero-password Gateway login (loopback or Tailscale) + `clearfills-desk sync ibkr`.
- **Any Bank Globally (RBC, Tangerine, TD, Chase, Amex, etc.):** Let your own AI agent read open bank tabs or PDF statements, mask account numbers to the last 3 digits, and call `sync_account_snapshot` via MCP.

---

## 4. Enable 1-Tap Live IBKR Execution

1. Configure your desk YAML (`execution_mode: live`, `ibkr.allow_live: true`, non-`DU*` account ID, port `4001`, per-sleeve caps, `human_confirm_above_usd: 25000`).
2. Validate fail-closed:
   ```bash
   CLEARFILLS_ALLOW_LIVE=1 clearfills-desk validate --config desk.live.yaml
   ```
3. Start the approval worker on your machine or private server:
   ```bash
   CLEARFILLS_ALLOW_LIVE=1 CLEARFILLS_API_KEY="cf_sk_..." \
     clearfills-desk watch --config desk.live.yaml --max-slippage-bps 50
   ```
4. Confirm **`Desk Worker: Online`** appears in **Inbox**.
5. When an agent previews an order above your threshold (or a Standing Mandate queues a treasury sweep capped at brokerage settled cash), tap **Approve** in **Inbox**. `clearfills-desk watch` atomically claims the order, verifies a fresh live quote within 50 bps, mints a fresh Ed25519 attestation, submits to IBKR, and writes the fill receipt back to **Inbox → Execution Receipts**.

---

## 5. Emergency Stop

Click **Trip** on the **Kill-Switch** in **Rules** (or call `trip_kill_switch`) at any time. All sleeves — including `cash_equivalent` and `core_index` — immediately fail closed until you explicitly **Re-arm**.
