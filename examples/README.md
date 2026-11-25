# ClearFills Ecosystem Examples

Runnable examples showing how to wrap popular AI trading frameworks and prediction market agents with ClearFills' deterministic pre-trade risk firewall and 1-Tap Approval Inbox. Every Python example runs locally with `--dry-run` and zero external API keys.

## Quick Run Commands

| Example | Framework / Venue | 1-Line Run Command |
| --- | --- | --- |
| [tradingagents_clearfills.py](tradingagents_clearfills.py) | `TauricResearch/TradingAgents` + IBKR / Alpaca | `python examples/tradingagents_clearfills.py --dry-run` |
| [ai_hedge_fund_clearfills.py](ai_hedge_fund_clearfills.py) | `virattt/ai-hedge-fund` + Multi-Entity Guards | `python examples/ai_hedge_fund_clearfills.py --dry-run` |
| [polymarket_metamask_agent.py](polymarket_metamask_agent.py) | Polymarket CLOB + MetaMask EIP-712 (`CTFExchange`) | `python examples/polymarket_metamask_agent.py --dry-run` |
| [tradingagents_safe_execution.py](tradingagents_safe_execution.py) | Local Ed25519 attestation + replay protection | `python examples/tradingagents_safe_execution.py` |
| [ai_hedge_fund_safe_execution.py](ai_hedge_fund_safe_execution.py) | Local sleeve rules + optional Cloud Inbox | `python examples/ai_hedge_fund_safe_execution.py` |
| [claude_mcp_setup.md](claude_mcp_setup.md) | Claude Desktop / Cursor MCP configuration | See setup guide |

## Connecting to ClearFills Cloud 1-Tap Approval Inbox

Export a ClearFills API key to queue firewall-attested orders into your Approval Inbox for Touch ID / WebAuthn or MetaMask EIP-712 sign-off:

```bash
export CLEARFILLS_API_KEY="cf_sk_..."
python examples/tradingagents_clearfills.py
```
