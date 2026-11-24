# Connecting AI Agents to ClearFills via MCP

ClearFills exposes two MCP modes so your AI agents can read portfolio state, evaluate standing mandates, and propose risk-checked trades without ever touching your broker passwords:

1. **Hosted Remote MCP (zero install):** `https://clearfills-api.fly.dev/mcp`
2. **Local Python MCP (`clearfills-firewall`):** `uvx --from clearfills-firewall clearfills-firewall-mcp`

Get an API key (`cf_sk_...`) anytime from [clearfills.com/console/rules](https://clearfills.com/console/rules) under **API Keys**, or use OAuth 2.1 directly in Claude.ai.

---

## 1. Claude.ai (Web & Desktop, OAuth 2.1)

No API key or local install required.

1. Open **Claude.ai** -> **Settings** -> **Connectors** -> **Add custom connector**.
2. Enter the Remote MCP URL:
   ```text
   https://clearfills-api.fly.dev/mcp
   ```
3. Click **Connect** and complete the OAuth 2.1 sign-in flow with your ClearFills account.

OAuth 2.1 Protected Resource Metadata is published at:
`https://clearfills-api.fly.dev/.well-known/oauth-protected-resource`

---

## 2. Claude Code (`claude mcp add`)

### Option A: Hosted Remote MCP (Recommended)

```bash
claude mcp add --transport http clearfills https://clearfills-api.fly.dev/mcp \
  --header "Authorization: Bearer cf_sk_your_api_key"
```

### Option B: Local Offline Firewall MCP (Zero Network)

```bash
claude mcp add clearfills -- uvx --from clearfills-firewall clearfills-firewall-mcp
```

### Option C: Cloud Trading OS over stdio

```bash
CLEARFILLS_API_KEY="cf_sk_your_api_key" \
  claude mcp add clearfills -- uvx --from clearfills-firewall clearfills-firewall-mcp --cloud
```

---

## 3. Cursor

Add to `.cursor/mcp.json` (project-level) or `~/.cursor/mcp.json` (global):

### Hosted Remote MCP

```json
{
  "mcpServers": {
    "clearfills": {
      "type": "http",
      "url": "https://clearfills-api.fly.dev/mcp",
      "headers": {
        "Authorization": "Bearer cf_sk_your_api_key"
      }
    }
  }
}
```

### Local Offline Firewall MCP

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

## 4. OpenAI Codex CLI

Add ClearFills to `~/.codex/config.toml`:

### Hosted Remote MCP

```toml
[mcp_servers.clearfills]
url = "https://clearfills-api.fly.dev/mcp"
http_headers = { Authorization = "Bearer cf_sk_your_api_key" }
```

### Local Offline Firewall MCP

```toml
[mcp_servers.clearfills]
command = "uvx"
args = ["--from", "clearfills-firewall", "clearfills-firewall-mcp"]
```

---

## 5. Verify Your Connection

Try this prompt in Claude, Claude Code, Cursor, or Codex:

> Check my ClearFills net worth and kill-switch status, then propose a $10,000 limit buy of SGOV on IBKR and return the firewall decision.

To try everything against a sample portfolio first, sign in at [clearfills.com/console](https://clearfills.com/console) and click **Launch 60-Second Sandbox Demo**.
