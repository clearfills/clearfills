# `clearfills-firewall`

[![License](https://img.shields.io/badge/License-Apache_2.0-10B981.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![PyPI](https://img.shields.io/pypi/v/clearfills-firewall.svg)](https://pypi.org/project/clearfills-firewall/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Deterministic Ed25519 pre-trade risk firewall, per-sleeve policy engine, SHA-256 hash-chained audit ledger, and MCP server for AI trading & wealth agents ([clearfills.com](https://clearfills.com)).

## Install

```bash
pip install clearfills-firewall
```

## Run as MCP Server

```bash
# Offline local firewall (zero network required)
clearfills-firewall-mcp

# Connected to ClearFills Cloud (Portfolio, Approvals, Standing Mandates, Lab)
CLEARFILLS_API_KEY="cf_sk_..." clearfills-firewall-mcp --cloud
```

Or connect directly to the hosted Streamable-HTTP MCP endpoint at `https://clearfills-api.fly.dev/mcp` with `Authorization: Bearer cf_sk_...` (no local install required).

## Key Features (`v0.4.0`)

- **Per-Sleeve Policy Routing (`SleevePolicy`):** Separate rules for `cash_equivalent` (`SGOV`, `BIL`, `CBIL`), `core_index` (`VT`, `VTI`, `VOO`, `SPY`), and `active_trading` (strict stop-loss, position risk, open heat, Friday/entry caps) while keeping kill-switch and daily drawdown limits fail-closed across all sleeves.
- **Single-Use Ed25519 Attestations:** 120-second TTL, cross-process `fcntl.flock` nonce replay protection (`NONCE_ALREADY_SPENT`), and `0600` key permissions.
- **SHA-256 Hash-Chained Audit Ledger:** Every approval, veto, and replay attempt is chained (`prev_hash -> entry_hash`) and independently verifiable.
- **Cloud MCP Tools (`--cloud`):** `get_net_worth` (live Bank of Canada `FXUSDCAD`), `sync_account_snapshot`, `propose_trade`, `submit_for_approval`, `list_approvals`, `list_mandates`, `evaluate_mandates`, `get_track_record`, `verify_audit_chain`, `manage_watchlist`, `save_research_note`, `log_trade_journal`, `run_backtest`.
- **Drop-In Agent Shims:** `TradingAgentsShim` and `AIHedgeFundShim`.

## Python Usage

```python
from clearfills_firewall import FirewallService, RiskPolicy, default_allocation_sleeves

policy = RiskPolicy(sleeves=default_allocation_sleeves())
svc = FirewallService(policy=policy)
decision = svc.evaluate(proposal, portfolio)
if decision.status == "APPROVED":
    svc.dispatch_check(proposal, decision.attestation)
```

*Non-custodial risk engineering software only. Not investment advice.*
