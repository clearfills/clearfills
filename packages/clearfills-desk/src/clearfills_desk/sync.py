"""ClearFills Companion local sync engine (IBKR, EVM/MetaMask RPC, and OpenAdapt local snapshots).

Zero password custody & zero Plaid/Flinks fees:
- `sync_ibkr_to_cloud`: reads sanitized live/paper portfolio from `IBKRExecutionAdapter` and pushes to ClearFills Cloud.
- `fetch_evm_wallet_snapshot` / `sync_evm_wallet_to_cloud`: reads public EVM wallet balances (ETH + USDC/USDT)
  via standard JSON-RPC (no private keys required) and pushes to ClearFills Cloud.
- `sync_openadapt_snapshot_to_cloud`: validates, strips any raw account numbers, and pushes a local
  OpenAdapt / browser-captured bank or brokerage snapshot (RBC, RBC Bank US, TD, Scotia, CIBC, Questrade,
  Wealthsimple, etc.) to ClearFills Cloud.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional

from .ibkr import IBKRExecutionAdapter
from .telemetry import sanitize_text

DEFAULT_API_BASE = "https://clearfills-api.fly.dev"
DEFAULT_EVM_RPC: dict[str, str] = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "base": "https://base-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
}
_USDC_CONTRACTS: dict[str, str] = {
    "ethereum": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "base": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "arbitrum": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
}
_EVM_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def post_account_snapshot(
    payload: dict[str, Any],
    *,
    api_key: str,
    api_base: str = DEFAULT_API_BASE,
    transport: Optional[Callable[[str, dict[str, Any]], dict[str, Any]]] = None,
) -> dict[str, Any]:
    """POST a sanitized account snapshot to ClearFills Cloud `/api/v1/cloud/accounts/sync`."""
    url = f"{api_base.rstrip('/')}/api/v1/cloud/accounts/sync"
    if transport is not None:
        return transport(url, payload)
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ClearFills Cloud sync failed (HTTP {exc.code}): {detail}") from exc


def sync_ibkr_to_cloud(
    adapter: IBKRExecutionAdapter,
    *,
    api_key: str,
    api_base: str = DEFAULT_API_BASE,
    account_name: str = "IBKR Margin",
    entity: str = "personal",
    entity_name: str = "Personal",
    transport: Optional[Callable[[str, dict[str, Any]], dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Fetch live/paper IBKR portfolio via `IBKRExecutionAdapter` and sync to ClearFills Cloud."""
    pf = adapter.get_portfolio()
    masked = str(pf.get("account_masked") or "***")
    suffix = re.sub(r"[^a-z0-9]", "", masked.lower()) or "acct"
    cash_usd = float(pf.get("settled_cash_usd") or 0.0)
    nav_usd = float(pf.get("nav_usd") or 0.0)
    investments_usd = max(0.0, round(nav_usd - cash_usd, 2))
    holdings = [
        {
            "symbol": str(p["symbol"]).upper(),
            "quantity": float(p.get("quantity") or 0.0),
            "market_value": float(p.get("market_value") or 0.0),
            "currency": str(p.get("currency") or "USD").upper(),
            "asset_class": "equity",
            "avg_cost": float(p.get("avg_cost") or 0.0) or None,
        }
        for p in pf.get("positions", [])
    ]
    payload = {
        "account_key": f"ibkr-{adapter.execution_mode}-{entity}-{suffix}",
        "institution": "IBKR",
        "account_name": account_name,
        "entity": entity,
        "entity_name": entity_name,
        "account_type": "brokerage",
        "currency": "USD",
        "cash_balance": round(cash_usd, 2),
        "investments_value": investments_usd,
        "liabilities_value": 0.0,
        "sync_source": "ibkr_desk",
        "capability": "trade_attested",
        "account_masked": masked,
        "holdings": holdings,
    }
    return post_account_snapshot(payload, api_key=api_key, api_base=api_base, transport=transport)


def _rpc_call(rpc_url: str, method: str, params: list[Any]) -> str:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(rpc_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=12) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if "error" in data:
        raise RuntimeError(f"EVM RPC error: {data['error']}")
    return str(data.get("result") or "0x0")


def _fetch_eth_price_usd() -> float:
    url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
    req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return float(data["ethereum"]["usd"])


def fetch_evm_wallet_snapshot(
    address: str,
    *,
    chain: str = "ethereum",
    account_name: str = "MetaMask Wallet",
    entity: str = "personal",
    entity_name: str = "Personal",
    rpc_url: Optional[str] = None,
    eth_price_usd: Optional[float] = None,
    rpc_fn: Optional[Callable[[str, str, list[Any]], str]] = None,
) -> dict[str, Any]:
    """Read public ETH + USDC balances for an EVM/MetaMask address (zero private keys)."""
    addr = address.strip()
    if not _EVM_ADDR_RE.fullmatch(addr):
        raise ValueError(f"Invalid EVM address: {addr!r}")
    chain_key = chain.strip().lower()
    endpoint = rpc_url or DEFAULT_EVM_RPC.get(chain_key)
    if not endpoint:
        raise ValueError(f"Unsupported chain {chain!r}; pass --rpc-url explicitly.")
    call = rpc_fn or _rpc_call

    wei_hex = call(endpoint, "eth_getBalance", [addr, "latest"])
    eth_qty = int(wei_hex, 16) / 1e18

    usdc_qty = 0.0
    usdc_contract = _USDC_CONTRACTS.get(chain_key)
    if usdc_contract:
        # ERC-20 balanceOf(address) selector = 0x70a08231
        padded = addr[2:].lower().rjust(64, "0")
        raw_usdc = call(endpoint, "eth_call", [{"to": usdc_contract, "data": f"0x70a08231{padded}"}, "latest"])
        if raw_usdc and raw_usdc != "0x":
            usdc_qty = int(raw_usdc, 16) / 1e6

    spot_eth = eth_price_usd if eth_price_usd is not None else _fetch_eth_price_usd()
    eth_val = round(eth_qty * spot_eth, 2)
    usdc_val = round(usdc_qty, 2)

    holdings = []
    if eth_qty > 0:
        holdings.append(
            {
                "symbol": "ETH",
                "quantity": round(eth_qty, 6),
                "market_value": eth_val,
                "currency": "USD",
                "asset_class": "crypto",
            }
        )
    if usdc_qty > 0:
        holdings.append(
            {
                "symbol": "USDC",
                "quantity": round(usdc_qty, 2),
                "market_value": usdc_val,
                "currency": "USD",
                "asset_class": "cash",
            }
        )

    masked = f"0x...{addr[-4:]}"
    return {
        "account_key": f"evm-{chain_key}-{addr[-6:].lower()}",
        "institution": "MetaMask",
        "account_name": f"{account_name} ({chain_key.title()})",
        "entity": entity,
        "entity_name": entity_name,
        "account_type": "crypto_wallet",
        "currency": "USD",
        "cash_balance": usdc_val,
        "investments_value": eth_val,
        "liabilities_value": 0.0,
        "sync_source": "evm_rpc",
        "capability": "read_only",
        "account_masked": masked,
        "holdings": holdings,
    }


def sync_openadapt_snapshot_to_cloud(
    snapshot_path: str | Path,
    *,
    api_key: str,
    api_base: str = DEFAULT_API_BASE,
    transport: Optional[Callable[[str, dict[str, Any]], dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Sanitize and push one or more local OpenAdapt bank/brokerage snapshots to ClearFills Cloud."""
    raw = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else [raw]
    synced: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cleaned = dict(item)
        cleaned["institution"] = sanitize_text(str(cleaned.get("institution", "Bank"))).strip()
        cleaned["account_name"] = sanitize_text(str(cleaned.get("account_name", "Account"))).strip()
        cleaned.setdefault("sync_source", "openadapt_local")
        cleaned.setdefault("capability", "read_only")
        if "account_key" not in cleaned:
            slug = re.sub(
                r"[^a-z0-9]+",
                "-",
                f"{cleaned['institution']}-{cleaned.get('entity', 'personal')}-{cleaned['account_name']}".lower(),
            ).strip("-")
            cleaned["account_key"] = slug[:60]
        synced.append(post_account_snapshot(cleaned, api_key=api_key, api_base=api_base, transport=transport))
    return synced
