# Isolated Worker Deployment Kit (Docker / Separate UID)

This kit runs `clearfills watch` (`clearfills-desk`) inside a hardened Docker container as a dedicated non-root user (`clearfills:clearfills`, UID `10001`) with a named Docker volume (`clearfills_state`) and `0600` file permissions.

**Why use this:** If you run an AI coding agent with shell access (Claude Code, Codex, Cursor terminal) under your normal desktop user, that agent can read `~/.clearfills/` keys or delete `killswitch.json` on the host. Isolating the execution worker into UID `10001` with a non-bind-mounted Docker volume removes same-UID file access. See [`../../EXECUTION_THREAT_MODEL.md`](../../EXECUTION_THREAT_MODEL.md) for the full threat model.

---

## 3-Step Setup

### Step 1: Generate a paper worker config
Create `deploy/isolated-worker/clearfills.yaml` (paper mode defaults to IBKR port `4002` and `allow_live: false`):

```bash
clearfills init --mode paper --output deploy/isolated-worker/clearfills.yaml
```

Edit `deploy/isolated-worker/clearfills.yaml` and set `ibkr.host` so the container can reach IB Gateway:
- **Local IB Gateway on the same machine:** set `host: host.docker.internal`
- **Remote IB Gateway over Tailscale (recommended):** set `host: 100.x.y.z` (your Tailscale IP)

### Step 2: Provide your operator credentials (outside the agent's shell)
Export `CLEARFILLS_API_KEY` in a dedicated operator terminal (do **not** add it to `~/.zshrc` or a workspace `.env` readable by your coding agent):

```bash
export CLEARFILLS_API_KEY="cf_sk_..."
# Hardware Passkey co-signing is ON by default (CLEARFILLS_REQUIRE_PASSKEY_COSIGN=1).
# Live execution stays OFF by default (CLEARFILLS_ALLOW_LIVE=0).
```

### Step 3: Build and start the isolated worker
From the repository root:

```bash
docker compose -f deploy/isolated-worker/docker-compose.isolated.yml up -d --build
docker compose -f deploy/isolated-worker/docker-compose.isolated.yml logs -f
```

---

## Security Defaults Included

| Control | Setting | Purpose |
| :--- | :--- | :--- |
| Non-root user | `10001:10001` (`clearfills:clearfills`) | Separate UID from host developer/agent user |
| State storage | Named volume `clearfills_state` (`0700` dir, `umask 0077` -> `0600` files) | Inaccessible to host coding-agent processes |
| Container hardening | `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true` | Prevents runtime binary/filesystem tampering |
| Passkey co-sign | `CLEARFILLS_REQUIRE_PASSKEY_COSIGN=1`, `CLEARFILLS_REQUIRE_PASSKEY_UV=1` | Enforces pinned WebAuthn Passkey verification on every order |
| Fail-closed live gate | `CLEARFILLS_ALLOW_LIVE=0` by default | Blocks live IBKR port `4001` until explicitly opted in |

## Switching to Live IBKR (After Paper Verification)

1. Verify paper execution end-to-end on port `4002` (`DU*` account).
2. Update `deploy/isolated-worker/clearfills.yaml` with `execution_mode: live`, `port: 4001`, your live account ID, and `allow_live: true`.
3. Restart with `CLEARFILLS_ALLOW_LIVE=1` set in your operator shell:

```bash
CLEARFILLS_ALLOW_LIVE=1 CLEARFILLS_API_KEY="cf_sk_..." \
  docker compose -f deploy/isolated-worker/docker-compose.isolated.yml up -d
```
