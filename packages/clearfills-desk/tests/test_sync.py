"""Unit tests for ClearFills Companion sync engine (IBKR, MetaMask EVM RPC, and OpenAdapt local snapshots)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from clearfills_desk.sync import (
    fetch_evm_wallet_snapshot,
    sync_openadapt_snapshot_to_cloud,
)


def test_fetch_evm_wallet_snapshot_parses_eth_and_usdc_without_keys() -> None:
    def fake_rpc(url: str, method: str, params: list[Any]) -> str:
        if method == "eth_getBalance":
            # 2.5 ETH in wei
            return hex(int(2.5 * 1e18))
        if method == "eth_call":
            # 12,500.50 USDC (6 decimals)
            return hex(int(12500.50 * 1e6))
        raise AssertionError(f"Unexpected RPC method {method}")

    snap = fetch_evm_wallet_snapshot(
        "0x111111111111111111111111111111111111AbCd",
        chain="ethereum",
        account_name="MetaMask Main",
        entity="personal",
        eth_price_usd=3000.0,
        rpc_fn=fake_rpc,
    )
    assert snap["institution"] == "MetaMask"
    assert snap["account_masked"] == "0x...AbCd"
    assert snap["cash_balance"] == 12500.5
    assert snap["investments_value"] == 7500.0
    assert snap["sync_source"] == "evm_rpc"
    assert len(snap["holdings"]) == 2


def test_sync_openadapt_snapshot_sanitizes_and_posts_multi_entity(tmp_path: Path) -> None:
    sample = [
        {
            "institution": "RBC",
            "account_name": "MLDSAI Inc. OpCo Chequing 12345678",
            "entity": "corporate",
            "entity_name": "MLDSAI Inc.",
            "account_type": "chequing",
            "currency": "CAD",
            "cash_balance": 145000.0,
            "investments_value": 0.0,
        },
        {
            "institution": "Questrade",
            "account_name": "Personal TFSA",
            "entity": "personal",
            "account_type": "tfsa",
            "currency": "CAD",
            "cash_balance": 4200.0,
            "investments_value": 98500.0,
        },
    ]
    p = tmp_path / "openadapt_snap.json"
    p.write_text(json.dumps(sample), encoding="utf-8")

    posted: list[dict[str, Any]] = []

    def fake_transport(url: str, payload: dict[str, Any]) -> dict[str, Any]:
        assert url.endswith("/api/v1/cloud/accounts/sync")
        posted.append(payload)
        return {"ok": True, **payload}

    res = sync_openadapt_snapshot_to_cloud(p, api_key="cf_sk_test", transport=fake_transport)
    assert len(res) == 2
    assert posted[0]["entity"] == "corporate"
    assert posted[0]["sync_source"] == "openadapt_local"
    assert posted[1]["institution"] == "Questrade"
    assert posted[1]["account_key"] == "questrade-personal-personal-tfsa"
