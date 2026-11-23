"""Unit tests for BrokerMCPServer, preview->execute flow, human confirm gate, cancel guards, and Tailnet validation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from clearfills_desk import (
    BrokerMCPServer,
    DeskConfig,
    DeskRuntime,
    IBKRConnectionConfig,
    IBKRExecutionAdapter,
    LiveExecutionSafetyError,
    validate_ibkr_connection,
)
from clearfills_firewall import RiskPolicy, default_allocation_sleeves

_FRIDAY_ET = datetime(2026, 11, 27, 19, 0, tzinfo=timezone.utc).isoformat()
_MONDAY_ET = datetime(2026, 11, 23, 15, 0, tzinfo=timezone.utc).isoformat()


class _FakeIB:
    """In-memory mock of ib_async.IB for deterministic end-to-end broker MCP testing."""

    def __init__(self, accounts: list[str]) -> None:
        self._accounts = accounts
        self._connected = False
        self.placed: list[tuple[Any, Any]] = []
        self.cancelled: list[int] = []
        self._next_oid = 100
        self._open_trades: list[Any] = [
            SimpleNamespace(
                order=SimpleNamespace(
                    orderId=501,
                    parentId=0,
                    action="BUY",
                    orderType="LMT",
                    totalQuantity=50,
                    lmtPrice=100.0,
                    auxPrice=0.0,
                    tif="DAY",
                    orderRef="clearfills:abc123",
                ),
                contract=SimpleNamespace(symbol="NVDA", currency="USD"),
                orderStatus=SimpleNamespace(status="Submitted"),
            ),
            SimpleNamespace(
                order=SimpleNamespace(
                    orderId=502,
                    parentId=501,
                    action="SELL",
                    orderType="STP",
                    totalQuantity=50,
                    lmtPrice=0.0,
                    auxPrice=95.0,
                    tif="GTC",
                    orderRef="clearfills:stop:abc123",
                ),
                contract=SimpleNamespace(symbol="NVDA", currency="USD"),
                orderStatus=SimpleNamespace(status="PreSubmitted"),
            ),
        ]

    def isConnected(self) -> bool:
        return self._connected

    def connect(self, host: str, port: int, clientId: int = 1, readonly: bool = False) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def managedAccounts(self) -> list[str]:
        return list(self._accounts)

    def accountSummary(self, account: str = "") -> list[Any]:
        return [
            SimpleNamespace(tag="NetLiquidation", currency="USD", value="500000.00"),
            SimpleNamespace(tag="BuyingPower", currency="USD", value="1000000.00"),
            SimpleNamespace(tag="SettledCash", currency="USD", value="225000.00"),
            SimpleNamespace(tag="SettledCash", currency="CAD", value="14500.00"),
            SimpleNamespace(tag="DailyPnL", currency="USD", value="420.50"),
        ]

    def portfolio(self, account: str = "") -> list[Any]:
        return [
            SimpleNamespace(
                contract=SimpleNamespace(symbol="VT", currency="USD"),
                position=400.0,
                averageCost=115.0,
                marketPrice=120.0,
                marketValue=48000.0,
                unrealizedPNL=2000.0,
            )
        ]

    def openTrades(self) -> list[Any]:
        return list(self._open_trades)

    def qualifyContracts(self, *contracts: Any) -> list[Any]:
        return list(contracts)

    def reqTickers(self, *contracts: Any) -> list[Any]:
        return [SimpleNamespace(bid=100.24, ask=100.26, last=100.25, close=100.20, vwap=100.25)]

    def whatIfOrder(self, contract: Any, order: Any) -> Any:
        return SimpleNamespace(
            initMarginChange="25000.0",
            maintMarginChange="25000.0",
            equityWithLoanAfter="499998.0",
            commission=1.05,
            minCommission=1.00,
            maxCommission=2.00,
            commissionCurrency="USD",
            warningText="",
        )

    def placeOrder(self, contract: Any, order: Any) -> Any:
        oid = self._next_oid
        self._next_oid += 1
        self.placed.append((contract, order))
        return SimpleNamespace(order=SimpleNamespace(orderId=oid))

    def cancelOrder(self, order: Any) -> None:
        oid = int(getattr(order, "orderId", 0))
        self.cancelled.append(oid)
        self._open_trades = [t for t in self._open_trades if t.order.orderId != oid]


def _make_live_server(tmp_path: Path) -> tuple[BrokerMCPServer, _FakeIB]:
    cfg = DeskConfig(
        desk_id="live-desk",
        desk_name="ClearFills Live Desk",
        execution_mode="live",
        human_confirm_above_usd=25_000.0,
        ibkr=IBKRConnectionConfig(
            host="clearfills-ib-live.example.ts.net",
            port=4001,
            account_id="U0000001",
            allow_live=True,
            allow_tailnet_relay=True,
        ),
        risk=RiskPolicy(
            max_risk_per_trade_pct=1.0,
            max_total_heat_pct=12.0,
            max_daily_loss_pct=2.0,
            max_order_notional_usd=50_000.0,
            require_stop_loss=True,
            max_entries_per_session=4,
            block_last_session_of_week=True,
            sleeves=default_allocation_sleeves(),
        ),
    )
    runtime = DeskRuntime(cfg, state_dir=tmp_path / "desk")
    fake_ib = _FakeIB(accounts=["U0000001"])
    adapter = IBKRExecutionAdapter(runtime, ib_client=fake_ib, env={"CLEARFILLS_ALLOW_LIVE": "1"})
    return BrokerMCPServer(adapter), fake_ib


def _call_tool(server: BrokerMCPServer, name: str, arguments: dict[str, Any] | None = None) -> tuple[dict[str, Any], bool]:
    resp = server.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}
    )
    assert resp is not None and "result" in resp
    res = resp["result"]
    payload = json.loads(res["content"][0]["text"])
    return payload, bool(res["isError"])


def test_get_portfolio_and_get_quote_sanitized(tmp_path: Path) -> None:
    server, _ = _make_live_server(tmp_path)
    pf, is_err = _call_tool(server, "get_portfolio")
    assert not is_err
    assert pf["account_masked"] == "***001"
    assert "U0000001" not in json.dumps(pf)
    assert pf["nav_usd"] == 500_000.0
    assert pf["settled_cash_usd"] == 225_000.0
    assert pf["settled_cash_cad"] == 14_500.0
    assert pf["positions"][0]["symbol"] == "VT"
    assert len(pf["open_orders"]) == 2

    q, q_err = _call_tool(server, "get_quote", {"symbol": "SGOV"})
    assert not q_err
    assert q["symbol"] == "SGOV"
    assert q["bid"] == 100.24
    assert q["ask"] == 100.26
    assert q["vwap"] == 100.25


def test_large_cash_equivalent_sleeve_requires_human_confirmation_then_executes(tmp_path: Path) -> None:
    server, fake_ib = _make_live_server(tmp_path)
    proposal = {
        "agent_id": "allocator-agent",
        "venue": "ibkr",
        "symbol": "SGOV",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 1000,
        "limit_price": 100.25,  # $100,250 >= $25,000 human_confirm_above_usd
        "created_at": _FRIDAY_ET,
    }
    preview, p_err = _call_tool(server, "preview_order", {"proposal": proposal})
    assert not p_err
    assert preview["approved"] is True
    assert preview["metrics"]["sleeve"] == "cash_equivalent"
    assert preview["requires_human_confirmation"] is True
    assert preview["what_if"]["available"] is True
    assert preview["what_if"]["commission"] == 1.05
    att_id = preview["attestation_id"]

    # Blocked without human_confirmed=True
    blocked, b_err = _call_tool(
        server,
        "execute_attested_order",
        {"proposal": proposal, "attestation_id": att_id, "human_confirmed": False},
    )
    assert b_err is True
    assert blocked["error"] == "HUMAN_CONFIRMATION_REQUIRED"
    assert len(fake_ib.placed) == 0

    # Succeeds once human_confirmed=True
    receipt, r_err = _call_tool(
        server,
        "execute_attested_order",
        {"proposal": proposal, "attestation_id": att_id, "human_confirmed": True},
    )
    assert not r_err
    assert receipt["execution_mode"] == "live"
    assert receipt["symbol"] == "SGOV"
    assert len(fake_ib.placed) == 1

    # Single-use attestation cannot be replayed
    replay, rep_err = _call_tool(
        server,
        "execute_attested_order",
        {"proposal": proposal, "attestation_id": att_id, "human_confirmed": True},
    )
    assert rep_err is True
    assert replay["error"] == "UNKNOWN_ATTESTATION_ID"


def test_active_swing_under_threshold_executes_without_human_gate(tmp_path: Path) -> None:
    server, fake_ib = _make_live_server(tmp_path)
    proposal = {
        "agent_id": "swing-bot",
        "venue": "ibkr",
        "symbol": "NVDA",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 100,
        "limit_price": 130.0,  # $13,000 < $25,000
        "stop_price": 120.0,  # $1,000 risk = 0.2% NAV
        "created_at": _MONDAY_ET,
    }
    preview, p_err = _call_tool(server, "preview_order", {"proposal": proposal})
    assert not p_err
    assert preview["approved"] is True
    assert preview["requires_human_confirmation"] is False

    receipt, r_err = _call_tool(
        server,
        "execute_attested_order",
        {"proposal": proposal, "attestation_id": preview["attestation_id"]},
    )
    assert not r_err
    assert receipt["symbol"] == "NVDA"
    assert len(fake_ib.placed) == 2  # Parent + protective stop


def test_cancel_order_protects_stop_loss_by_default(tmp_path: Path) -> None:
    server, fake_ib = _make_live_server(tmp_path)

    # Refuses to cancel protective stop 502 without force_cancel_stop=True
    blocked, b_err = _call_tool(server, "cancel_order", {"order_id": 502})
    assert b_err is True
    assert blocked["error"] == "SAFETY_GUARD_BLOCKED"
    assert 502 not in fake_ib.cancelled

    # Allows cancelling normal limit order 501
    ok, ok_err = _call_tool(server, "cancel_order", {"order_id": 501})
    assert not ok_err
    assert ok["cancelled"] is True
    assert 501 in fake_ib.cancelled

    # Allows cancelling stop 502 when explicitly forced
    forced, f_err = _call_tool(server, "cancel_order", {"order_id": 502, "force_cancel_stop": True})
    assert not f_err
    assert forced["cancelled"] is True
    assert forced["was_protective_stop"] is True


def test_tailnet_relay_validation_paper_and_live() -> None:
    # Paper over Tailnet port 4004 succeeds when allow_tailnet_relay=True
    validate_ibkr_connection(
        IBKRConnectionConfig(host="ib-paper.example.ts.net", port=4004, account_id="DU0000001", allow_tailnet_relay=True),
        "paper",
    )
    # Paper refuses 4004 when allow_tailnet_relay=False
    with pytest.raises(LiveExecutionSafetyError, match="refuses port 4004"):
        validate_ibkr_connection(
            IBKRConnectionConfig(host="127.0.0.1", port=4004, account_id="DU0000001", allow_tailnet_relay=False),
            "paper",
        )
    # Live over Tailnet port 4001 succeeds with two-key opt-in
    validate_ibkr_connection(
        IBKRConnectionConfig(
            host="100.100.10.20", port=4001, account_id="U0000001", allow_live=True, allow_tailnet_relay=True
        ),
        "live",
        env={"CLEARFILLS_ALLOW_LIVE": "1"},
    )
    # Live refuses public IP even when allow_tailnet_relay=True
    with pytest.raises(LiveExecutionSafetyError, match="non-loopback"):
        validate_ibkr_connection(
            IBKRConnectionConfig(
                host="8.8.8.8", port=4001, account_id="U0000001", allow_live=True, allow_tailnet_relay=True
            ),
            "live",
            env={"CLEARFILLS_ALLOW_LIVE": "1"},
        )
    # Live refuses paper tailnet port 4004
    with pytest.raises(LiveExecutionSafetyError, match="refuses port 4004"):
        validate_ibkr_connection(
            IBKRConnectionConfig(
                host="clearfills-ib-live.example.ts.net",
                port=4004,
                account_id="U0000001",
                allow_live=True,
                allow_tailnet_relay=True,
            ),
            "live",
            env={"CLEARFILLS_ALLOW_LIVE": "1"},
        )
