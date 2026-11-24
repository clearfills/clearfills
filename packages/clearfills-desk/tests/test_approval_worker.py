"""Offline unit tests for ApprovalWorker (1-Tap Approve & Execute -> IBKR bridge)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from clearfills_desk import (
    ApprovalWorker,
    CloudHTTPError,
    DeskConfig,
    DeskRuntime,
    IBKRConnectionConfig,
    IBKRExecutionAdapter,
)
from clearfills_desk.cli import main as cli_main
from clearfills_firewall import RiskPolicy, default_allocation_sleeves


class _FakeIB:
    """In-memory mock of ib_async.IB for deterministic offline ApprovalWorker tests."""

    def __init__(
        self,
        accounts: list[str] | None = None,
        *,
        bid: float = 100.20,
        ask: float = 100.25,
        last: float = 100.22,
    ) -> None:
        self._accounts = accounts or ["U0000001"]
        self._connected = False
        self.bid = bid
        self.ask = ask
        self.last = last
        self.placed: list[tuple[Any, Any]] = []
        self.quote_calls: list[Any] = []
        self._next_oid = 7001

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
            SimpleNamespace(tag="SettledCash", currency="USD", value="250000.00"),
            SimpleNamespace(tag="DailyPnL", currency="USD", value="150.00"),
        ]

    def portfolio(self, account: str = "") -> list[Any]:
        return [
            SimpleNamespace(
                contract=SimpleNamespace(symbol="VT", currency="USD"),
                position=200.0,
                averageCost=115.0,
                marketPrice=120.0,
                marketValue=24000.0,
                unrealizedPNL=1000.0,
            )
        ]

    def openTrades(self) -> list[Any]:
        return []

    def qualifyContracts(self, *contracts: Any) -> list[Any]:
        return list(contracts)

    def reqTickers(self, *contracts: Any) -> list[Any]:
        self.quote_calls.extend(contracts)
        return [
            SimpleNamespace(
                bid=self.bid,
                ask=self.ask,
                last=self.last,
                close=self.last,
                vwap=self.last,
                marketDataType=1,
            )
        ]

    def placeOrder(self, contract: Any, order: Any) -> Any:
        oid = self._next_oid
        self._next_oid += 1
        self.placed.append((contract, order))
        return SimpleNamespace(order=SimpleNamespace(orderId=oid))


def _make_adapter(
    tmp_path: Path,
    *,
    bid: float = 100.20,
    ask: float = 100.25,
    last: float = 100.22,
) -> tuple[IBKRExecutionAdapter, _FakeIB]:
    cfg = DeskConfig(
        desk_id="live-worker-desk",
        desk_name="ClearFills Live Worker Desk",
        execution_mode="live",
        human_confirm_above_usd=25_000.0,
        ibkr=IBKRConnectionConfig(
            host="127.0.0.1",
            port=4001,
            account_id="U0000001",
            allow_live=True,
        ),
        risk=RiskPolicy(
            max_risk_per_trade_pct=1.0,
            max_total_heat_pct=12.0,
            max_daily_loss_pct=2.0,
            max_order_notional_usd=50_000.0,
            require_stop_loss=True,
            max_entries_per_session=4,
            block_last_session_of_week=False,
            sleeves=default_allocation_sleeves(),
        ),
    )
    runtime = DeskRuntime(cfg, state_dir=tmp_path / "desk_state")
    fake_ib = _FakeIB(bid=bid, ask=ask, last=last)
    adapter = IBKRExecutionAdapter(runtime, ib_client=fake_ib, env={"CLEARFILLS_ALLOW_LIVE": "1"})
    return adapter, fake_ib


def test_happy_path_approved_ibkr_order_claimed_attested_and_executed(tmp_path: Path) -> None:
    adapter, fake_ib = _make_adapter(tmp_path, bid=100.20, ask=100.30, last=100.25)
    calls: list[tuple[str, str, Any]] = []

    def fake_transport(method: str, path: str, body: Any) -> Any:
        calls.append((method, path, body))
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return [
                {
                    "approval_id": "apr_live_001",
                    "status": "approved",
                    "venue": "ibkr",
                    "symbol": "SGOV",
                    "side": "BUY",
                    "order_type": "LIMIT",
                    "quantity": 300,
                    "limit_price": 100.25,
                    "agent_id": "allocator-agent",
                }
            ]
        if method == "POST" and path == "/api/v1/cloud/approvals/apr_live_001/claim":
            return {"approval_id": "apr_live_001", "claimed": True}
        if method == "POST" and path == "/api/v1/cloud/approvals/apr_live_001/executed":
            return {"approval_id": "apr_live_001", "status": "executed"}
        raise AssertionError(f"Unexpected cloud request: {method} {path}")

    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        max_slippage_bps=50.0,
        cloud_transport=fake_transport,
    )
    outcomes = worker.poll_once()

    assert len(outcomes) == 1
    out = outcomes[0]
    assert out["approval_id"] == "apr_live_001"
    assert out["symbol"] == "SGOV"
    assert out["status"] == "submitted"
    assert out["broker_order_id"] == "7001"
    assert out["fill_price"] == pytest.approx(100.30)
    assert out["attestation_id"]
    assert out["receipt"]["symbol"] == "SGOV"
    assert out["receipt"]["order_ids"] == [7001]

    # Exactly 1 order placed on IBKR
    assert len(fake_ib.placed) == 1

    # Verify cloud call sequence: heartbeat -> GET -> claim -> executed
    assert [c[:2] for c in calls] == [
        ("POST", "/api/v1/cloud/worker/heartbeat"),
        ("GET", "/api/v1/cloud/approvals?status=approved"),
        ("POST", "/api/v1/cloud/approvals/apr_live_001/claim"),
        ("POST", "/api/v1/cloud/approvals/apr_live_001/executed"),
    ]
    hb_body = calls[0][2]
    assert hb_body == {
        "worker_id": worker.worker_id,
        "venue": "ibkr",
        "execution_mode": "live",
        "account_masked": "***001",
        "max_slippage_bps": 50.0,
        "dry_run": False,
    }
    exec_body = calls[3][2]
    assert exec_body["status"] == "submitted"
    assert exec_body["broker_order_id"] == "7001"
    assert exec_body["fill_price"] == pytest.approx(100.30)
    assert exec_body["receipt"]["attestation_id"] == out["attestation_id"]


def test_slippage_guard_fails_closed_and_reports_slippage_rejected(tmp_path: Path) -> None:
    # Approved limit is 100.00, fresh ask jumped to 101.20 (+120 bps > 50 bps max)
    adapter, fake_ib = _make_adapter(tmp_path, bid=101.10, ask=101.20, last=101.15)
    calls: list[tuple[str, str, Any]] = []

    def fake_transport(method: str, path: str, body: Any) -> Any:
        calls.append((method, path, body))
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return [
                {
                    "approval_id": "apr_slip_002",
                    "status": "approved",
                    "venue": "ibkr",
                    "symbol": "SGOV",
                    "side": "BUY",
                    "order_type": "LIMIT",
                    "quantity": 100,
                    "limit_price": 100.00,
                }
            ]
        if method == "POST" and path == "/api/v1/cloud/approvals/apr_slip_002/claim":
            return {"claimed": True}
        if method == "POST" and path == "/api/v1/cloud/approvals/apr_slip_002/executed":
            return {"ok": True}
        raise AssertionError(f"Unexpected cloud request: {method} {path}")

    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        max_slippage_bps=50.0,
        cloud_transport=fake_transport,
    )
    outcomes = worker.poll_once()

    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "slippage_rejected"
    assert outcomes[0]["slippage_bps"] == pytest.approx(120.0)
    # Zero IBKR orders submitted
    assert len(fake_ib.placed) == 0

    exec_calls = [c for c in calls if c[1].endswith("/executed")]
    assert len(exec_calls) == 1
    assert exec_calls[0][2]["status"] == "slippage_rejected"
    assert "120.0 bps" in exec_calls[0][2]["detail"]


def test_claim_conflict_409_skips_cleanly_without_submitting(tmp_path: Path) -> None:
    adapter, fake_ib = _make_adapter(tmp_path)
    calls: list[tuple[str, str, Any]] = []

    def fake_transport(method: str, path: str, body: Any) -> Any:
        calls.append((method, path, body))
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return [
                {
                    "approval_id": "apr_race_003",
                    "status": "approved",
                    "venue": "ibkr",
                    "symbol": "SGOV",
                    "side": "BUY",
                    "order_type": "LIMIT",
                    "quantity": 50,
                    "limit_price": 100.25,
                }
            ]
        if method == "POST" and path == "/api/v1/cloud/approvals/apr_race_003/claim":
            raise CloudHTTPError(409, "Approval already claimed")
        raise AssertionError(f"Unexpected cloud request after 409: {method} {path}")

    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        cloud_transport=fake_transport,
    )
    outcomes = worker.poll_once()

    assert len(outcomes) == 1
    assert outcomes[0]["approval_id"] == "apr_race_003"
    assert outcomes[0]["status"] == "claim_conflict"
    assert len(fake_ib.quote_calls) == 0
    assert len(fake_ib.placed) == 0
    assert len(calls) == 3


def test_non_ibkr_venue_clearfills_sandbox_is_ignored(tmp_path: Path) -> None:
    adapter, fake_ib = _make_adapter(tmp_path)
    calls: list[tuple[str, str, Any]] = []

    def fake_transport(method: str, path: str, body: Any) -> Any:
        calls.append((method, path, body))
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return [
                {
                    "approval_id": "apr_sandbox_004",
                    "status": "approved",
                    "venue": "clearfills_sandbox",
                    "symbol": "NVDA",
                    "side": "BUY",
                    "quantity": 10,
                    "limit_price": 135.0,
                }
            ]
        raise AssertionError(f"Non-IBKR approval should not trigger claim/execute: {method} {path}")

    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        cloud_transport=fake_transport,
    )
    outcomes = worker.poll_once()

    assert outcomes == []
    assert len(fake_ib.quote_calls) == 0
    assert len(fake_ib.placed) == 0
    assert len(calls) == 2


def test_dry_run_validates_and_attests_without_ibkr_submit(tmp_path: Path) -> None:
    adapter, fake_ib = _make_adapter(tmp_path, bid=100.22, ask=100.26, last=100.24)
    calls: list[tuple[str, str, Any]] = []

    def fake_transport(method: str, path: str, body: Any) -> Any:
        calls.append((method, path, body))
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return [
                {
                    "approval_id": "apr_dry_005",
                    "status": "approved",
                    "venue": "ibkr",
                    "symbol": "SGOV",
                    "side": "BUY",
                    "order_type": "LIMIT",
                    "quantity": 200,
                    "limit_price": 100.25,
                }
            ]
        raise AssertionError(f"Dry run should not mutate cloud state: {method} {path}")

    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        max_slippage_bps=50.0,
        dry_run=True,
        cloud_transport=fake_transport,
    )
    outcomes = worker.poll_once()

    assert len(outcomes) == 1
    out = outcomes[0]
    assert out["approval_id"] == "apr_dry_005"
    assert out["status"] == "dry_run_ready"
    assert out["fresh_price"] == pytest.approx(100.26)
    assert out["attestation_id"]
    # Quote was fetched, but zero orders submitted to IBKR
    assert len(fake_ib.quote_calls) == 1
    assert len(fake_ib.placed) == 0


def test_firewall_denied_when_kill_switch_tripped(tmp_path: Path) -> None:
    adapter, fake_ib = _make_adapter(tmp_path, bid=100.20, ask=100.25, last=100.22)
    adapter.runtime.firewall.kill_switch.trip(actor="operator", reason="operator emergency halt")
    calls: list[tuple[str, str, Any]] = []

    def fake_transport(method: str, path: str, body: Any) -> Any:
        calls.append((method, path, body))
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return [
                {
                    "approval_id": "apr_ks_006",
                    "status": "approved",
                    "venue": "ibkr",
                    "symbol": "SGOV",
                    "side": "BUY",
                    "order_type": "LIMIT",
                    "quantity": 100,
                    "limit_price": 100.25,
                }
            ]
        if method == "POST" and path == "/api/v1/cloud/approvals/apr_ks_006/claim":
            return {"claimed": True}
        if method == "POST" and path == "/api/v1/cloud/approvals/apr_ks_006/executed":
            return {"ok": True}
        raise AssertionError(f"Unexpected cloud request: {method} {path}")

    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        cloud_transport=fake_transport,
    )
    outcomes = worker.poll_once()

    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "firewall_denied"
    assert len(fake_ib.placed) == 0
    exec_calls = [c for c in calls if c[1].endswith("/executed")]
    assert len(exec_calls) == 1
    assert exec_calls[0][2]["status"] == "firewall_denied"


def test_cli_watch_requires_api_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("CLEARFILLS_API_KEY", raising=False)
    cfg_path = tmp_path / "desk.yaml"
    cfg_path.write_text("desk_id: d1\ndesk_name: D1\nexecution_mode: paper\n", encoding="utf-8")

    rc = cli_main(["watch", "--config", str(cfg_path), "--once", "--dry-run"])
    assert rc == 2
    payload = json.loads(capsys.readouterr().out)
    assert "CLEARFILLS_API_KEY" in payload["error"]


def test_heartbeat_sent_on_first_poll_and_throttled_to_15s(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, _ = _make_adapter(tmp_path)
    calls: list[tuple[str, str, Any]] = []
    now_clock = [1000.0]

    monkeypatch.setattr("clearfills_desk.worker.time.monotonic", lambda: now_clock[0])

    def fake_transport(method: str, path: str, body: Any) -> Any:
        calls.append((method, path, body))
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return []
        raise AssertionError(f"Unexpected cloud request: {method} {path}")

    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        max_slippage_bps=35.0,
        dry_run=True,
        cloud_transport=fake_transport,
        worker_id="worker-ibkr-01",
    )

    # First poll always sends heartbeat
    worker.poll_once()
    heartbeats = [c for c in calls if c[:2] == ("POST", "/api/v1/cloud/worker/heartbeat")]
    assert len(heartbeats) == 1
    assert heartbeats[0][2] == {
        "worker_id": "worker-ibkr-01",
        "venue": "ibkr",
        "execution_mode": "live",
        "account_masked": "***001",
        "max_slippage_bps": 35.0,
        "dry_run": True,
    }

    # Second poll within 15s is throttled
    now_clock[0] += 10.0
    worker.poll_once()
    heartbeats = [c for c in calls if c[:2] == ("POST", "/api/v1/cloud/worker/heartbeat")]
    assert len(heartbeats) == 1

    # Third poll after >= 15s sends heartbeat again
    now_clock[0] += 5.0
    worker.poll_once()
    heartbeats = [c for c in calls if c[:2] == ("POST", "/api/v1/cloud/worker/heartbeat")]
    assert len(heartbeats) == 2


def test_heartbeat_404_or_offline_never_crashes_poll_once(tmp_path: Path) -> None:
    adapter, _ = _make_adapter(tmp_path)
    calls: list[tuple[str, str, Any]] = []

    def fake_transport(method: str, path: str, body: Any) -> Any:
        calls.append((method, path, body))
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            raise CloudHTTPError(404, "Not Found")
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return []
        raise AssertionError(f"Unexpected cloud request: {method} {path}")

    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        cloud_transport=fake_transport,
    )
    assert worker.poll_once() == []
    assert [c[:2] for c in calls] == [
        ("POST", "/api/v1/cloud/worker/heartbeat"),
        ("GET", "/api/v1/cloud/approvals?status=approved"),
    ]
