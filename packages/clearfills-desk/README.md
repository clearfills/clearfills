# ClearFills Desk OS (`clearfills-desk`)

Open-source, bring-your-own-LLM, bring-your-own-strategy **6-Agent Trading Desk** architecture with **`clearfills-firewall>=0.2.0`** as the sole deterministic pre-trade risk authority.

## Architecture (6 Roles, Zero Broker Keys for LLMs)

1. **Researcher** — gathers filings, catalysts, and market data (read-only).
2. **Strategist** — proposes structured `TradeProposal` intents with explicit entry, stop-loss, and thesis citations.
3. **Risk Officer** — delegates deterministically to `clearfills-firewall` (`RiskPolicy` YAML: per-trade risk, total open heat, session entry caps, ET cutoff time, Friday entry block, daily loss kill-switch, and 120s single-use Ed25519 attestations).
4. **Trader (Execution Gateway)** — verifies the single-use Ed25519 attestation via `dispatch_check()` before routing to IBKR / Alpaca / Polymarket / Paper.
5. **Chief of Staff** — relays operator desk decisions and monitors heartbeats / Slack alerts.
6. **Auditor** — verifies the SHA-256 hash-chained audit ledger and publishes sanitized heartbeats + Strategy Receipts to the ClearFills Arena.

## Quickstart

```python
from pathlib import Path
from clearfills_desk import DeskConfig, DeskRuntime, IBKRExecutionAdapter

cfg = DeskConfig.from_yaml(Path("config/desk_rules.example.yaml"))
runtime = DeskRuntime(config=cfg, state_dir=Path("./state"))
decision = runtime.evaluate_proposal(proposal, portfolio)

# Paper (4002/7497 + DU*) or Live (4001/7496 + non-DU* + two-key opt-in)
adapter = IBKRExecutionAdapter(runtime)
receipt = adapter.submit_attested_order(proposal, decision.attestation)
```

## Live IBKR Execution (Fail-Closed Two-Key Opt-In)

Live trading is **refused by default**. To connect a capped live IBKR Gateway sleeve (e.g., port `4001`, US\$25k–\$50k notional cap):

1. Start IB Gateway on loopback (`127.0.0.1:4001`, or a local Tailscale relay with `ibkr.allow_tailnet_relay: true`).
2. Copy `config/desk_rules.live.example.yaml`, set your non-`DU` live `account_id`, set `execution_mode: live`, and set `ibkr.allow_live: true`.
3. Export the second key in the execution environment only: `export CLEARFILLS_ALLOW_LIVE=1`.
4. Validate fail-closed before connecting:
   ```bash
   CLEARFILLS_ALLOW_LIVE=1 clearfills-desk validate --config config/desk_rules.live.example.yaml
   ```
5. Every live order passes `clearfills-firewall` single-use Ed25519 `dispatch_check()` in Enforce mode before touching IBKR, submits parent + protective stop-loss bracket legs, and returns a sanitized `ExecutionReceipt` (zero account IDs).

> **Non-custodial software:** ClearFills Desk OS does not hold funds, execute managed capital, or provide investment advice. Plug in your own private strategies, LLM keys, and broker credentials.
