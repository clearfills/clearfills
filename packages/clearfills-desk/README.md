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
from clearfills_desk import DeskConfig, DeskRuntime

cfg = DeskConfig.from_yaml(Path("config/desk_rules.example.yaml"))
runtime = DeskRuntime(config=cfg, state_dir=Path("./state"))
decision = runtime.evaluate_proposal(proposal, portfolio)
```

> **Non-custodial software:** ClearFills Desk OS does not hold funds, execute managed capital, or provide investment advice. Plug in your own private strategies, LLM keys, and broker credentials.
