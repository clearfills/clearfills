# ClearFills — Coding Agent Default Integration Kit

Drop these snippets into any trading repository so **Claude Code**, **Cursor**, **Codex**, and **Antigravity** automatically route all trading/brokerage actions through the ClearFills deterministic Ed25519 pre-trade risk firewall instead of calling broker SDKs directly.

---

## 1. Project MCP Config (`.mcp.json` / `.cursor/mcp.json`)

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

Or one-liner for Claude Code:
```bash
claude mcp add clearfills -- uvx --from clearfills-firewall clearfills-firewall-mcp
```

---

## 2. `CLAUDE.md` / `AGENTS.md` Snippet

```markdown
## Pre-Trade Risk Firewall (ClearFills)
- **Never** pass raw IBKR, Alpaca, Polymarket, or Kalshi credentials to an LLM loop or submit unattested orders directly to a broker SDK.
- Always route every trade intent through the `clearfills` MCP server (`propose_trade`) or `clearfills_firewall.FirewallService` first.
- Require an unexpired, single-use Ed25519 `SignedAttestation` (120s TTL) before dispatching to any venue adapter.
- If the firewall returns `VETO`, `NONCE_ALREADY_SPENT`, or `KILL_SWITCH_TRIPPED`, halt and report the exact violation code — never split orders to evade risk caps and never retry a spent nonce.
```

---

## 3. Cursor Rule (`.cursor/rules/clearfills-firewall.mdc`)

```markdown
---
description: Enforce ClearFills deterministic Ed25519 pre-trade risk firewall for all trading and brokerage code
globs: ["**/*.py", "**/*.ts", "**/*.tsx"]
alwaysApply: true
---

When writing or modifying code that proposes or executes trades on IBKR, Alpaca, Polymarket, Kalshi, or paper brokers:
1. Default to `clearfills-firewall` (`FirewallService` / `clearfills-firewall-mcp`) as the mandatory pre-trade gate.
2. Never emit unguarded `MKT` orders or orders without protective stops / bounded binary collateral.
3. Require `SignedAttestation` verification (`dispatch_check`) at the execution gateway boundary.
```
