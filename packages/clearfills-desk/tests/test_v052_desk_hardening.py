"""Unit tests for v0.5.2 ClearFills Desk hardening (IBKR contract currency, MARKET block, short/stop snapshot, directional slippage)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from clearfills_desk import (
    ApprovalWorker,
    BrokerMCPServer,
    DeskConfig,
    DeskRuntime,
    IBKRConnectionConfig,
    IBKRExecutionAdapter,
    LiveExecutionSafetyError,
)
from clearfills_desk.ibkr import _resolve_stock_contract_spec
from clearfills_firewall import (
    OrderType,
    RiskPolicy,
    Side,
    TradeProposal,
    default_allocation_sleeves,
)


class _MockIB:
    def __init__(
        self,
        accounts: list[str] | None = None,
        *,
        bid: float = 100.0,
        ask: float = 100.05,
        last: float = 100.02,
        positions: list[Any] | None = None,
        open_trades: list[Any] | None = None,
    ) -> None:
        self._accounts = accounts or ["DU0000001"]
        self._connected = False
        self.bid = bid
        self.ask = ask
        self.last = last
        self._positions = positions or []
        self._open_trades = open_trades or []
        self.qualified: list[Any] = []
        self.tickers_requested: list[Any] = []
        self.placed: list[tuple[Any, Any]] = []
        self._next_oid = 8001

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
            SimpleNamespace(tag="NetLiquidation", currency="USD", value="200000.00"),
            SimpleNamespace(tag="SettledCash", currency="USD", value="150000.00"),
            SimpleNamespace(tag="SettledCash", currency="CAD", value="50000.00"),
            SimpleNamespace(tag="DailyPnL", currency="USD", value="0.00"),
        ]

    def portfolio(self, account: str = "") -> list[Any]:
        return list(self._positions)

    def openTrades(self) -> list[Any]:
        return list(self._open_trades)

    def qualifyContracts(self, *contracts: Any) -> list[Any]:
        self.qualified.extend(contracts)
        return list(contracts)

    def reqTickers(self, *contracts: Any) -> list[Any]:
        self.tickers_requested.extend(contracts)
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


def _make_paper_adapter(
    tmp_path: Path,
    *,
    ib_client: _MockIB | None = None,
    allow_market_orders: bool = False,
    allow_shorting: bool = False,
) -> tuple[IBKRExecutionAdapter, _MockIB]:
    cfg = DeskConfig(
        desk_id="paper-hardening-desk",
        desk_name="Paper Hardening Desk",
        execution_mode="paper",
        ibkr=IBKRConnectionConfig(
            host="127.0.0.1",
            port=4002,
            account_id="DU0000001",
            allow_live=False,
        ),
        risk=RiskPolicy(
            max_risk_per_trade_pct=2.0,
            max_total_heat_pct=12.0,
            max_order_notional_usd=100_000.0,
            allow_market_orders=allow_market_orders,
            allow_shorting=allow_shorting,
            sleeves=default_allocation_sleeves(),
        ),
    )
    rt = DeskRuntime(cfg, state_dir=tmp_path / f"state_{allow_market_orders}_{allow_shorting}")
    mock_ib = ib_client or _MockIB()
    adapter = IBKRExecutionAdapter(rt, ib_client=mock_ib, env={})
    return adapter, mock_ib


def test_ibkr_adapter_refuses_market_order_with_safety_error(tmp_path: Path) -> None:
    adapter, mock_ib = _make_paper_adapter(tmp_path, allow_market_orders=False)
    mkt_proposal = TradeProposal(
        agent_id="rogue-bot",
        venue="ibkr",
        symbol="NVDA",
        side=Side.BUY,
        order_type=OrderType.MARKET,
        quantity=10.0,
        limit_price=135.0,
        stop_price=125.0,
    )

    # Direct contract/order builder fails closed before building orders
    with pytest.raises(LiveExecutionSafetyError, match="non-LIMIT"):
        adapter._build_contract_and_orders(mkt_proposal, "DU0000001", "att_test_12345678")

    # Even if an attestation were issued directly by the authority, submit_attested_order fails closed
    forged_or_manual_att = adapter.runtime.firewall.authority.issue(mkt_proposal)
    with pytest.raises(LiveExecutionSafetyError, match="non-LIMIT"):
        adapter.submit_attested_order(mkt_proposal, forged_or_manual_att)
    assert len(mock_ib.placed) == 0

    # LIMIT order missing limit_price also fails closed
    limit_missing_price = TradeProposal(
        agent_id="rogue-bot",
        venue="ibkr",
        symbol="NVDA",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=10.0,
        limit_price=None,
        stop_price=125.0,
    )
    with pytest.raises(LiveExecutionSafetyError, match="positive limit_price"):
        adapter._build_contract_and_orders(limit_missing_price, "DU0000001", "att_test_12345678")


def test_tsx_cad_and_dot_to_currency_resolution(tmp_path: Path) -> None:
    assert _resolve_stock_contract_spec("CBIL") == ("CBIL", "SMART", "CAD")
    assert _resolve_stock_contract_spec("RY.TO") == ("RY", "SMART", "CAD")
    assert _resolve_stock_contract_spec("ry.to", currency="USD") == ("RY", "SMART", "CAD")
    assert _resolve_stock_contract_spec("SGOV") == ("SGOV", "SMART", "USD")

    adapter, mock_ib = _make_paper_adapter(tmp_path, ib_client=_MockIB(bid=49.99, ask=50.01, last=50.00))
    server = BrokerMCPServer(adapter)

    # MCP get_quote without currency argument resolves CAD for CBIL and RY.TO, USD for SGOV
    for raw_sym, expected_sym, expected_ccy in [
        ("CBIL", "CBIL", "CAD"),
        ("RY.TO", "RY", "CAD"),
        ("SGOV", "SGOV", "USD"),
    ]:
        resp = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "get_quote", "arguments": {"symbol": raw_sym}},
            }
        )
        assert resp is not None
        quote = json.loads(resp["result"]["content"][0]["text"])
        assert resp["result"]["isError"] is False
        assert quote["symbol"] == expected_sym
        assert quote["currency"] == expected_ccy

    # Order contract builder also resolves CAD for CBIL and RY.TO
    cbil_prop = TradeProposal(
        agent_id="allocator",
        venue="ibkr",
        symbol="CBIL",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=100.0,
        limit_price=50.0,
    )
    cbil_contract, _ = adapter._build_contract_and_orders(cbil_prop, "DU0000001", "att_cbil_00000001")
    cbil_ccy = cbil_contract["currency"] if isinstance(cbil_contract, dict) else cbil_contract.currency
    cbil_sym = cbil_contract["symbol"] if isinstance(cbil_contract, dict) else cbil_contract.symbol
    assert cbil_sym == "CBIL"
    assert cbil_ccy == "CAD"

    ry_prop = TradeProposal(
        agent_id="swing",
        venue="ibkr",
        symbol="RY.TO",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=20.0,
        limit_price=170.0,
        stop_price=162.0,
    )
    ry_contract, _ = adapter._build_contract_and_orders(ry_prop, "DU0000001", "att_ryto_00000001")
    ry_ccy = ry_contract["currency"] if isinstance(ry_contract, dict) else ry_contract.currency
    ry_sym = ry_contract["symbol"] if isinstance(ry_contract, dict) else ry_contract.symbol
    assert ry_sym == "RY"
    assert ry_ccy == "CAD"


def test_build_portfolio_snapshot_includes_shorts_and_maps_protective_stops(tmp_path: Path) -> None:
    adapter, _ = _make_paper_adapter(tmp_path)
    portfolio_data = {
        "account_masked": "***001",
        "nav_usd": 200_000.0,
        "settled_cash_usd": 120_000.0,
        "daily_pnl_usd": -250.0,
        "positions": [
            {
                "symbol": "NVDA",
                "quantity": 100.0,
                "avg_cost": 130.0,
                "market_price": 135.0,
            },
            {
                "symbol": "TSLA",
                "quantity": -50.0,
                "avg_cost": 250.0,
                "market_price": 240.0,
            },
        ],
        "open_orders": [
            {
                "order_id": 101,
                "symbol": "NVDA",
                "action": "SELL",
                "order_type": "STP",
                "aux_price": 126.0,
                "is_protective_stop": True,
            },
            {
                "order_id": 102,
                "symbol": "TSLA",
                "action": "BUY",
                "order_type": "STP",
                "aux_price": 262.0,
                "is_protective_stop": True,
            },
        ],
    }

    snap = adapter.build_portfolio_snapshot(portfolio_data)
    assert snap.open_position_count == 2
    by_sym = {p.symbol: p for p in snap.open_positions}

    assert by_sym["NVDA"].quantity == 100.0
    assert by_sym["NVDA"].stop_price == pytest.approx(126.0)

    assert by_sym["TSLA"].quantity == -50.0
    assert by_sym["TSLA"].stop_price == pytest.approx(262.0)


def test_approval_worker_directional_slippage_and_stale_gap_guard(tmp_path: Path) -> None:
    # 1. BUY with favorable price improvement (-75 bps: limit=100.00, ask=99.25) -> SUBMITTED
    buy_ib = _MockIB(bid=99.20, ask=99.25, last=99.22)
    buy_adapter, _ = _make_paper_adapter(tmp_path / "buy_fav", ib_client=buy_ib)

    def buy_fav_transport(method: str, path: str, body: Any) -> Any:
        if path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return [
                {
                    "approval_id": "apr_buy_fav",
                    "status": "approved",
                    "venue": "ibkr",
                    "symbol": "SGOV",
                    "side": "BUY",
                    "order_type": "LIMIT",
                    "quantity": 100,
                    "limit_price": 100.00,
                }
            ]
        if path.endswith("/claim"):
            return {"claimed": True}
        if path.endswith("/executed"):
            return {"ok": True}
        raise AssertionError(f"Unexpected request: {method} {path}")

    worker_buy = ApprovalWorker(
        adapter=buy_adapter,
        api_key="cf_test",
        max_slippage_bps=50.0,
        cloud_transport=buy_fav_transport,
    )
    res_buy = worker_buy.poll_once()
    assert len(res_buy) == 1
    assert res_buy[0]["status"] == "submitted"
    assert res_buy[0]["slippage_bps"] == pytest.approx(-75.0)
    assert len(buy_ib.placed) == 1

    # 2. SELL with favorable price improvement (-80 bps: limit=100.00, bid=100.80) -> SUBMITTED
    sell_positions = [
        SimpleNamespace(
            contract=SimpleNamespace(symbol="SGOV", currency="USD"),
            position=200.0,
            averageCost=100.0,
            marketPrice=100.80,
            marketValue=20160.0,
            unrealizedPNL=160.0,
        )
    ]
    sell_ib = _MockIB(bid=100.80, ask=100.85, last=100.82, positions=sell_positions)
    sell_adapter, _ = _make_paper_adapter(tmp_path / "sell_fav", ib_client=sell_ib)

    def sell_fav_transport(method: str, path: str, body: Any) -> Any:
        if path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return [
                {
                    "approval_id": "apr_sell_fav",
                    "status": "approved",
                    "venue": "ibkr",
                    "symbol": "SGOV",
                    "side": "SELL",
                    "order_type": "LIMIT",
                    "quantity": 100,
                    "limit_price": 100.00,
                }
            ]
        if path.endswith("/claim"):
            return {"claimed": True}
        if path.endswith("/executed"):
            return {"ok": True}
        raise AssertionError(f"Unexpected request: {method} {path}")

    worker_sell = ApprovalWorker(
        adapter=sell_adapter,
        api_key="cf_test",
        max_slippage_bps=50.0,
        cloud_transport=sell_fav_transport,
    )
    res_sell = worker_sell.poll_once()
    assert len(res_sell) == 1
    assert res_sell[0]["status"] == "submitted"
    assert res_sell[0]["slippage_bps"] == pytest.approx(-80.0)
    assert len(sell_ib.placed) == 1

    # 3. SELL with adverse slippage (+70 bps: limit=100.00, bid=99.30) -> SLIPPAGE_REJECTED
    sell_adv_ib = _MockIB(bid=99.30, ask=99.35, last=99.32, positions=sell_positions)
    sell_adv_adapter, _ = _make_paper_adapter(tmp_path / "sell_adv", ib_client=sell_adv_ib)
    worker_sell_adv = ApprovalWorker(
        adapter=sell_adv_adapter,
        api_key="cf_test",
        max_slippage_bps=50.0,
        cloud_transport=sell_fav_transport,
    )
    res_sell_adv = worker_sell_adv.poll_once()
    assert len(res_sell_adv) == 1
    assert res_sell_adv[0]["status"] == "slippage_rejected"
    assert res_sell_adv[0]["slippage_bps"] == pytest.approx(70.0)
    assert len(sell_adv_ib.placed) == 0

    # 4. Extreme >1000 bps favorable gap (e.g. stale quote / split: BUY limit=100.00, ask=85.00 -> 1500 bps) -> SLIPPAGE_REJECTED
    stale_ib = _MockIB(bid=84.95, ask=85.00, last=84.98)
    stale_adapter, _ = _make_paper_adapter(tmp_path / "buy_stale", ib_client=stale_ib)
    worker_stale = ApprovalWorker(
        adapter=stale_adapter,
        api_key="cf_test",
        max_slippage_bps=50.0,
        cloud_transport=buy_fav_transport,
    )
    res_stale = worker_stale.poll_once()
    assert len(res_stale) == 1
    assert res_stale[0]["status"] == "slippage_rejected"
    assert res_stale[0]["slippage_bps"] == pytest.approx(-1500.0)
    assert len(stale_ib.placed) == 0
