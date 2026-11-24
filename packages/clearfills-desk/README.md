# `clearfills-desk`

Open-source broker execution layer, MCP server, and 1-tap approval worker powered by [`clearfills-firewall`](https://pypi.org/project/clearfills-firewall/) ([clearfills.com](https://clearfills.com)).

AI agents **never hold broker credentials**. `clearfills-desk` connects to your local or Tailscale-meshed IBKR Gateway, enforces deterministic Ed25519 risk attestations before any order touches the broker, and bridges your ClearFills Cloud `Inbox` to live execution.

## CLI Commands

```bash
# 1. Validate a paper or live YAML config (fail-closed)
clearfills-desk validate --config config/desk_rules.example.yaml
CLEARFILLS_ALLOW_LIVE=1 clearfills-desk validate --config config/desk_rules.live.example.yaml

# 2. Sync live balances & holdings into ClearFills Cloud Net Worth
clearfills-desk sync ibkr --config desk.live.yaml
clearfills-desk sync evm --address 0x... --entity personal
clearfills-desk sync file --path accounts.json

# 3. Run the 1-tap Approval Queue execution worker (polls Cloud Inbox every 3s)
CLEARFILLS_ALLOW_LIVE=1 CLEARFILLS_API_KEY="cf_sk_..." \
  clearfills-desk watch --config desk.live.yaml --max-slippage-bps 50

# Safe dry-run test (verifies heartbeat + quote + firewall without transmitting orders)
CLEARFILLS_ALLOW_LIVE=1 CLEARFILLS_API_KEY="cf_sk_..." \
  clearfills-desk watch --config desk.live.yaml --once --dry-run
```

## MCP Server (`clearfills-desk-mcp`)

Attach `clearfills-desk-mcp` to Claude Code, Codex, or Cursor:

| Tool | What It Does |
| :--- | :--- |
| `get_portfolio` | Live NAV, settled USD/CAD cash, `accrued_interest_usd`, buying power, positions, open orders (masked account IDs). |
| `get_quote` | Bid/ask/last/close/VWAP with `market_data_type`, `is_delayed`, and stale-close warnings. |
| `preview_order` | Runs `clearfills-firewall` + IBKR `whatIfOrder` margin preview + Ed25519 attestation; auto-queues orders >= `human_confirm_above_usd` into ClearFills Cloud `Inbox`. |
| `execute_attested_order` | Submits an attested limit/bracket order (blocks above `human_confirm_above_usd` without explicit confirmation). |
| `execute_approved_order` | Verifies Cloud `status == "approved"` and matches symbol/side/qty before executing and posting the broker receipt back. |
| `list_open_orders` | Lists active orders with protective stop-loss flags. |
| `cancel_order` | Cancels an order while refusing to cancel protective stops unless `force_cancel_stop=true`. |

## Safety Invariants

- **Paper vs. Live Hard Separation:** Paper requires port `4002`/`4004`/`7497` + `DU*` account; Live requires port `4001`/`7496` + non-`DU*` account + `ibkr.allow_live: true` + `CLEARFILLS_ALLOW_LIVE=1`.
- **Host Guard:** Refuses public IPs. Allows loopback (`127.0.0.1`) or Tailscale (`100.64.0.0/10` with `allow_tailnet_relay: true`) only.
- **Multi-Agent Coexistence:** Automatically retries `clientId` collisions (`base_id` to `base_id + 5`) so Claude Code, Codex, and CLI commands can share one IB Gateway.
- **Atomic Claim & 50 bps Slippage Guard (`watch`):** Claims approved orders atomically (`approved -> executing`), checks fresh live quotes within `max_slippage_bps`, mints a fresh Ed25519 attestation, and sends a 15-second worker heartbeat to `Inbox`.

*Non-custodial execution software only. Not investment advice.*
