"""Attested IBKR Paper & Live execution adapter for ClearFills Desk OS.

Fail-closed guarantees:
1. Loopback-only host (127.0.0.1 / localhost / Tailnet loopback relay).
2. Strict port & account separation:
   - Paper mode: ports {4002, 7497} and accounts prefixed with "DU".
   - Live mode:  ports {4001, 7496}, non-"DU" account_id, `ibkr.allow_live=True`,
                 AND environment variable `CLEARFILLS_ALLOW_LIVE=1`.
3. Every order MUST pass `DeskRuntime.verify_dispatch(attestation, proposal)`
   (Ed25519 signature, 120s TTL, single-use nonce, exact order-spec binding)
   before any broker API call is made.
4. Never leaks raw account numbers in receipts or telemetry.
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

from clearfills_firewall import (
    OrderType,
    PortfolioSnapshot,
    Position,
    Side,
    SignedAttestation,
    TradeProposal,
)

from .runtime import DeskRuntime, IBKRConnectionConfig

PAPER_PORTS: frozenset[int] = frozenset({4002, 7497})
PAPER_TAILNET_PORTS: frozenset[int] = frozenset({4002, 4004, 7497})
LIVE_PORTS: frozenset[int] = frozenset({4001, 7496})
PAPER_PREFIX = "DU"
LIVE_ENV_FLAG = "CLEARFILLS_ALLOW_LIVE"
_TAILSCALE_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_STOP_ORDER_TYPES: frozenset[str] = frozenset({"STP", "STP LMT", "TRAIL", "TRAIL LIMIT"})


def mask_account_id(account_id: str) -> str:
    """Mask an IBKR account ID to its last 3 characters for safe telemetry/logs."""
    cleaned = account_id.strip()
    if len(cleaned) <= 3:
        return "***"
    return f"***{cleaned[-3:]}"


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        num = float(value)
        if num != num:  # NaN check
            return default
        return num
    except (TypeError, ValueError):
        return default


def _is_allowed_host(host: str, *, allow_tailnet_relay: bool = False) -> bool:
    cleaned = host.strip().lower()
    if cleaned == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(cleaned)
        if ip.is_loopback:
            return True
        if allow_tailnet_relay and isinstance(ip, ipaddress.IPv4Address) and ip in _TAILSCALE_CGNAT:
            return True
        return False
    except ValueError:
        if allow_tailnet_relay and cleaned.endswith(".ts.net"):
            return True
        return False


class LiveExecutionSafetyError(RuntimeError):
    """Raised when an IBKR execution request fails a hard paper/live safety guard."""


class ExecutionReceipt(BaseModel):
    """Sanitized execution receipt safe for logs and public Arena telemetry."""

    execution_mode: Literal["paper", "live"]
    venue: str = "ibkr"
    symbol: str
    side: str
    quantity: float
    order_type: str
    limit_price: float | None = None
    stop_price: float | None = None
    target_price: float | None = None
    order_ids: list[int] = Field(default_factory=list)
    attestation_id: str
    submitted_at: str


class _IBClientProtocol(Protocol):
    """Minimal subset of `ib_async.IB` used by `IBKRExecutionAdapter`."""

    def isConnected(self) -> bool: ...
    def connect(self, host: str, port: int, clientId: int = ..., readonly: bool = ...) -> Any: ...
    def disconnect(self) -> Any: ...
    def managedAccounts(self) -> list[str]: ...
    def qualifyContracts(self, *contracts: Any) -> list[Any]: ...
    def placeOrder(self, contract: Any, order: Any) -> Any: ...


def validate_ibkr_connection(
    cfg: IBKRConnectionConfig,
    execution_mode: Literal["paper", "live"],
    *,
    env: dict[str, str] | None = None,
) -> None:
    """Validate host, port, account prefix, and two-key live opt-in (fail closed)."""
    if not _is_allowed_host(cfg.host, allow_tailnet_relay=cfg.allow_tailnet_relay):
        raise LiveExecutionSafetyError(
            f"Refusing non-loopback IBKR host {cfg.host!r}; use 127.0.0.1 / localhost or enable allow_tailnet_relay for a Tailscale relay."
        )

    if execution_mode == "paper":
        allowed_paper_ports = PAPER_TAILNET_PORTS if cfg.allow_tailnet_relay else PAPER_PORTS
        if cfg.port not in allowed_paper_ports:
            raise LiveExecutionSafetyError(
                f"Paper mode refuses port {cfg.port}; allowed paper ports: {sorted(allowed_paper_ports)}."
            )
        if cfg.account_id and not cfg.account_id.startswith(PAPER_PREFIX):
            raise LiveExecutionSafetyError(
                f"Paper mode refuses non-paper account {cfg.account_id!r} (must start with {PAPER_PREFIX!r})."
            )
        return

    if execution_mode == "live":
        if not cfg.allow_live:
            raise LiveExecutionSafetyError(
                "Live mode requires `ibkr.allow_live: true` in DeskConfig."
            )
        env_map = os.environ if env is None else env
        if env_map.get(LIVE_ENV_FLAG) != "1":
            raise LiveExecutionSafetyError(
                f"Live mode requires environment variable {LIVE_ENV_FLAG}=1 (two-key safety guard)."
            )
        if cfg.port not in LIVE_PORTS:
            raise LiveExecutionSafetyError(
                f"Live mode refuses port {cfg.port}; allowed live ports: {sorted(LIVE_PORTS)}."
            )
        if not cfg.account_id:
            raise LiveExecutionSafetyError(
                "Live mode requires an explicit `ibkr.account_id` (e.g. U1234567)."
            )
        if cfg.account_id.startswith(PAPER_PREFIX):
            raise LiveExecutionSafetyError(
                f"Live mode refuses paper account {cfg.account_id!r}."
            )
        return

    raise LiveExecutionSafetyError(f"Unsupported execution_mode: {execution_mode!r}")


def verify_connected_accounts(
    managed_accounts: list[str],
    expected_account: str | None,
    execution_mode: Literal["paper", "live"],
) -> str:
    """Verify the connected IBKR session's managed accounts match paper/live mode."""
    if not managed_accounts:
        raise LiveExecutionSafetyError("IBKR Gateway returned no managed accounts.")

    if execution_mode == "paper":
        non_paper = [a for a in managed_accounts if not a.startswith(PAPER_PREFIX)]
        if non_paper:
            raise LiveExecutionSafetyError(
                f"Paper mode connected to non-paper account(s): {non_paper}."
            )
        account = expected_account or managed_accounts[0]
        if account not in managed_accounts:
            raise LiveExecutionSafetyError(
                f"Expected paper account {account!r} not in managed accounts {managed_accounts}."
            )
        return account

    # Live mode
    if not expected_account:
        raise LiveExecutionSafetyError("Live mode requires an explicit expected_account.")
    if expected_account.startswith(PAPER_PREFIX):
        raise LiveExecutionSafetyError("Live mode cannot target a paper DU account.")
    if expected_account not in managed_accounts:
        raise LiveExecutionSafetyError(
            f"Expected live account {expected_account!r} not found in connected gateway accounts."
        )
    return expected_account


class IBKRExecutionAdapter:
    """Routes ClearFills-attested orders to IBKR Gateway/TWS (Paper or Live)."""

    def __init__(
        self,
        runtime: DeskRuntime,
        *,
        ib_client: _IBClientProtocol | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        if runtime.config.execution_mode == "shadow":
            raise LiveExecutionSafetyError(
                "IBKRExecutionAdapter refuses execution_mode='shadow' (shadow mode must never route orders to IBKR)."
            )
        self.runtime = runtime
        self._env = env
        self._ib = ib_client
        self._mode: Literal["paper", "live"] = (
            "live" if runtime.config.execution_mode == "live" else "paper"
        )
        validate_ibkr_connection(runtime.config.ibkr, self._mode, env=self._env)

    @property
    def execution_mode(self) -> Literal["paper", "live"]:
        return self._mode

    def _get_client(self) -> _IBClientProtocol:
        if self._ib is not None:
            return self._ib
        try:
            from ib_async import IB  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "ib_async is required for live/paper IBKR connectivity. "
                "Install with: pip install 'clearfills-desk[ibkr]'"
            ) from exc
        self._ib = IB()
        return self._ib

    def connect(self, *, readonly: bool = False) -> str:
        """Connect to IBKR Gateway/TWS and verify the active account matches mode."""
        cfg = self.runtime.config.ibkr
        validate_ibkr_connection(cfg, self._mode, env=self._env)
        ib = self._get_client()
        if not ib.isConnected():
            ib.connect(cfg.host, cfg.port, clientId=cfg.client_id, readonly=readonly)
        return verify_connected_accounts(ib.managedAccounts(), cfg.account_id, self._mode)

    def disconnect(self) -> None:
        if self._ib is not None and self._ib.isConnected():
            self._ib.disconnect()

    def _build_stock_contract(self, symbol: str, *, exchange: str = "SMART", currency: str = "USD") -> Any:
        try:
            from ib_async import Stock  # type: ignore[import-not-found]
            return Stock(symbol.strip().upper(), exchange, currency)
        except ImportError:
            return {"symbol": symbol.strip().upper(), "exchange": exchange, "currency": currency}

    def list_open_orders(self) -> list[dict[str, Any]]:
        """List open orders sanitized of raw account IDs."""
        self.connect(readonly=True)
        ib = self._get_client()
        open_trades = getattr(ib, "openTrades", lambda: [])()
        results: list[dict[str, Any]] = []
        for tr in open_trades:
            order = getattr(tr, "order", None)
            contract = getattr(tr, "contract", None)
            status_obj = getattr(tr, "orderStatus", None)
            order_type = str(getattr(order, "orderType", "") or "").upper()
            order_ref = str(getattr(order, "orderRef", "") or "")
            is_stop = order_type in _STOP_ORDER_TYPES or order_ref.startswith("clearfills:stop:")
            results.append(
                {
                    "order_id": int(getattr(order, "orderId", 0) or 0),
                    "parent_id": int(getattr(order, "parentId", 0) or 0),
                    "symbol": str(getattr(contract, "symbol", "") or "").upper(),
                    "action": str(getattr(order, "action", "") or "").upper(),
                    "order_type": order_type,
                    "quantity": _safe_float(getattr(order, "totalQuantity", 0.0)),
                    "limit_price": _safe_float(getattr(order, "lmtPrice", 0.0)) or None,
                    "aux_price": _safe_float(getattr(order, "auxPrice", 0.0)) or None,
                    "tif": str(getattr(order, "tif", "") or ""),
                    "status": str(getattr(status_obj, "status", "Unknown") or "Unknown"),
                    "order_ref": order_ref,
                    "is_protective_stop": is_stop,
                }
            )
        return results

    def get_portfolio(self) -> dict[str, Any]:
        """Fetch live NAV, settled USD/CAD cash, buying power, positions, and open orders (sanitized)."""
        account = self.connect(readonly=True)
        ib = self._get_client()

        summary_rows = getattr(ib, "accountSummary", lambda _acct="": [])(account)
        if not summary_rows and hasattr(ib, "accountValues"):
            summary_rows = ib.accountValues(account)

        nav_usd = 0.0
        buying_power_usd = 0.0
        daily_pnl_usd = 0.0
        cash_by_currency: dict[str, float] = {}
        settled_by_currency: dict[str, float] = {}

        for row in summary_rows:
            tag = str(getattr(row, "tag", "") or "")
            ccy = str(getattr(row, "currency", "") or "").upper()
            val = _safe_float(getattr(row, "value", 0.0))
            if tag == "NetLiquidation" and ccy in {"USD", "BASE", ""}:
                nav_usd = val
            elif tag == "BuyingPower" and ccy in {"USD", "BASE", ""}:
                buying_power_usd = val
            elif tag in {"RealizedPnL", "DailyPnL"} and ccy in {"USD", "BASE", ""}:
                daily_pnl_usd = val
            elif tag == "TotalCashBalance" and ccy and ccy != "BASE":
                cash_by_currency[ccy] = val
            elif tag == "SettledCash" and ccy and ccy != "BASE":
                settled_by_currency[ccy] = val
            elif tag == "TotalCashValue" and ccy in {"USD", "CAD"} and ccy not in cash_by_currency:
                cash_by_currency[ccy] = val

        settled_usd = settled_by_currency.get("USD", cash_by_currency.get("USD", 0.0))
        settled_cad = settled_by_currency.get("CAD", cash_by_currency.get("CAD", 0.0))

        raw_positions = getattr(ib, "portfolio", lambda _acct="": [])(account)
        if not raw_positions and hasattr(ib, "positions"):
            raw_positions = ib.positions(account)

        positions: list[dict[str, Any]] = []
        for item in raw_positions:
            contract = getattr(item, "contract", None)
            sym = str(getattr(contract, "symbol", "") or "").upper()
            qty = _safe_float(getattr(item, "position", 0.0))
            if not sym or qty == 0.0:
                continue
            avg_cost = _safe_float(getattr(item, "averageCost", getattr(item, "avgCost", 0.0)))
            mkt_price = _safe_float(getattr(item, "marketPrice", avg_cost), avg_cost)
            mkt_val = _safe_float(getattr(item, "marketValue", qty * mkt_price), qty * mkt_price)
            unrealized = _safe_float(getattr(item, "unrealizedPNL", 0.0))
            ccy = str(getattr(contract, "currency", "USD") or "USD").upper()
            positions.append(
                {
                    "symbol": sym,
                    "quantity": qty,
                    "avg_cost": round(avg_cost, 6),
                    "market_price": round(mkt_price, 6),
                    "market_value": round(mkt_val, 2),
                    "unrealized_pnl": round(unrealized, 2),
                    "currency": ccy,
                }
            )

        open_orders = self.list_open_orders()
        return {
            "execution_mode": self._mode,
            "venue": "ibkr",
            "account_masked": mask_account_id(account),
            "nav_usd": round(nav_usd, 2),
            "settled_cash_usd": round(settled_usd, 2),
            "settled_cash_cad": round(settled_cad, 2),
            "cash_by_currency": {k: round(v, 2) for k, v in sorted(cash_by_currency.items())},
            "buying_power_usd": round(buying_power_usd, 2),
            "daily_pnl_usd": round(daily_pnl_usd, 2),
            "positions": positions,
            "open_orders": open_orders,
            "as_of": datetime.now(timezone.utc).isoformat(),
        }

    def build_portfolio_snapshot(self, portfolio_data: dict[str, Any] | None = None) -> PortfolioSnapshot:
        """Convert sanitized `get_portfolio()` output into a `PortfolioSnapshot` for firewall evaluation."""
        data = portfolio_data if portfolio_data is not None else self.get_portfolio()
        open_positions = [
            Position(
                symbol=str(p["symbol"]).upper(),
                quantity=float(p["quantity"]),
                avg_entry_price=max(0.0001, float(p.get("avg_cost") or p.get("market_price") or 1.0)),
                current_price=max(0.0001, float(p.get("market_price") or p.get("avg_cost") or 1.0)),
                venue="ibkr",
            )
            for p in data.get("positions", [])
            if float(p.get("quantity", 0.0)) > 0
        ]
        nav = max(1.0, float(data.get("nav_usd") or 1.0))
        cash = max(0.0, float(data.get("settled_cash_usd") or 0.0))
        return PortfolioSnapshot(
            account_id=str(data.get("account_masked") or "***"),
            nav_usd=nav,
            cash_usd=cash,
            daily_pnl_usd=float(data.get("daily_pnl_usd") or 0.0),
            open_positions=open_positions,
        )

    def get_quote(self, symbol: str, *, exchange: str = "SMART", currency: str = "USD") -> dict[str, Any]:
        """Fetch live snapshot bid/ask/last/VWAP quote from IBKR Gateway."""
        self.connect(readonly=True)
        ib = self._get_client()
        contract = self._build_stock_contract(symbol, exchange=exchange, currency=currency)
        qualified = ib.qualifyContracts(contract)
        if qualified:
            contract = qualified[0]

        ticker = None
        if hasattr(ib, "reqTickers"):
            tickers = ib.reqTickers(contract)
            ticker = tickers[0] if tickers else None
        elif hasattr(ib, "reqMktData"):
            ticker = ib.reqMktData(contract, "", snapshot=True)

        bid = _safe_float(getattr(ticker, "bid", None), 0.0) if ticker is not None else 0.0
        ask = _safe_float(getattr(ticker, "ask", None), 0.0) if ticker is not None else 0.0
        last = _safe_float(getattr(ticker, "last", None), 0.0) if ticker is not None else 0.0
        close = _safe_float(getattr(ticker, "close", None), 0.0) if ticker is not None else 0.0
        vwap = _safe_float(getattr(ticker, "vwap", None), 0.0) if ticker is not None else 0.0
        return {
            "symbol": symbol.strip().upper(),
            "exchange": exchange,
            "currency": currency,
            "bid": bid if bid > 0 else None,
            "ask": ask if ask > 0 else None,
            "last": last if last > 0 else None,
            "close": close if close > 0 else None,
            "vwap": vwap if vwap > 0 else None,
            "as_of": datetime.now(timezone.utc).isoformat(),
        }

    def what_if_order(self, proposal: TradeProposal) -> dict[str, Any]:
        """Run IBKR `whatIfOrder` margin & commission preview without transmitting an order."""
        account = self.connect(readonly=True)
        ib = self._get_client()
        contract, orders = self._build_contract_and_orders(
            proposal=proposal,
            account=account,
            attestation_id="whatif-preview",
        )
        qualified = ib.qualifyContracts(contract)
        if qualified:
            contract = qualified[0]
        parent = orders[0]
        if not hasattr(ib, "whatIfOrder"):
            return {"available": False, "reason": "IB client does not expose whatIfOrder"}
        state = ib.whatIfOrder(contract, parent)
        return {
            "available": True,
            "init_margin_change": getattr(state, "initMarginChange", None),
            "maint_margin_change": getattr(state, "maintMarginChange", None),
            "equity_with_loan_after": getattr(state, "equityWithLoanAfter", None),
            "commission": _safe_float(getattr(state, "commission", None), 0.0) or None,
            "min_commission": _safe_float(getattr(state, "minCommission", None), 0.0) or None,
            "max_commission": _safe_float(getattr(state, "maxCommission", None), 0.0) or None,
            "commission_currency": getattr(state, "commissionCurrency", "USD"),
            "warning_text": getattr(state, "warningText", "") or "",
        }

    def cancel_order(self, order_id: int, *, force_cancel_stop: bool = False) -> dict[str, Any]:
        """Cancel an open order while preserving protective stop-loss cancel guards."""
        self.connect(readonly=False)
        ib = self._get_client()
        open_trades = getattr(ib, "openTrades", lambda: [])()
        target_trade = None
        for tr in open_trades:
            if int(getattr(getattr(tr, "order", None), "orderId", -1)) == int(order_id):
                target_trade = tr
                break
        if target_trade is None:
            raise LiveExecutionSafetyError(f"Open order {order_id} not found.")

        order = getattr(target_trade, "order", None)
        contract = getattr(target_trade, "contract", None)
        order_type = str(getattr(order, "orderType", "") or "").upper()
        order_ref = str(getattr(order, "orderRef", "") or "")
        is_stop = order_type in _STOP_ORDER_TYPES or order_ref.startswith("clearfills:stop:")
        if is_stop and not force_cancel_stop:
            raise LiveExecutionSafetyError(
                f"Refusing to cancel protective stop-loss order {order_id} ({order_type}); pass force_cancel_stop=True only after flattening or replacing the stop."
            )

        ib.cancelOrder(order)
        return {
            "cancelled": True,
            "order_id": int(order_id),
            "symbol": str(getattr(contract, "symbol", "") or "").upper(),
            "order_type": order_type,
            "was_protective_stop": is_stop,
        }

    def _build_contract_and_orders(
        self,
        proposal: TradeProposal,
        account: str,
        attestation_id: str,
    ) -> tuple[Any, list[Any]]:
        """Build IBKR Stock contract + parent/stop/target order objects."""
        try:
            from ib_async import LimitOrder, MarketOrder, Order, Stock  # type: ignore[import-not-found]
        except ImportError:
            # Lightweight fallback dicts for unit-testing with injected mock clients
            contract = {"symbol": proposal.symbol.upper(), "exchange": "SMART", "currency": "USD"}
            parent = {
                "account": account,
                "action": proposal.side.value,
                "totalQuantity": proposal.quantity,
                "orderType": "LMT" if proposal.order_type == OrderType.LIMIT else "MKT",
                "lmtPrice": proposal.limit_price,
                "orderRef": f"clearfills:{attestation_id[:16]}",
                "transmit": proposal.stop_price is None and proposal.target_price is None,
            }
            orders = [parent]
            if proposal.stop_price is not None:
                exit_action = "SELL" if proposal.side == Side.BUY else "BUY"
                orders.append(
                    {
                        "account": account,
                        "action": exit_action,
                        "totalQuantity": proposal.quantity,
                        "orderType": "STP",
                        "auxPrice": proposal.stop_price,
                        "orderRef": f"clearfills:stop:{attestation_id[:16]}",
                        "transmit": proposal.target_price is None,
                    }
                )
            if proposal.target_price is not None:
                exit_action = "SELL" if proposal.side == Side.BUY else "BUY"
                orders.append(
                    {
                        "account": account,
                        "action": exit_action,
                        "totalQuantity": proposal.quantity,
                        "orderType": "LMT",
                        "lmtPrice": proposal.target_price,
                        "orderRef": f"clearfills:tp:{attestation_id[:16]}",
                        "transmit": True,
                    }
                )
            return contract, orders

        contract = Stock(proposal.symbol.upper(), "SMART", "USD")
        action = proposal.side.value
        exit_action = "SELL" if proposal.side == Side.BUY else "BUY"
        has_children = proposal.stop_price is not None or proposal.target_price is not None

        if proposal.order_type == OrderType.LIMIT:
            if proposal.limit_price is None:
                raise LiveExecutionSafetyError("LIMIT order requires limit_price.")
            parent = LimitOrder(action, proposal.quantity, proposal.limit_price)
        else:
            parent = MarketOrder(action, proposal.quantity)
        parent.account = account
        parent.tif = "DAY"
        parent.orderRef = f"clearfills:{attestation_id[:16]}"
        parent.transmit = not has_children

        orders: list[Any] = [parent]
        if proposal.stop_price is not None:
            stop = Order(
                action=exit_action,
                totalQuantity=proposal.quantity,
                orderType="STP",
                auxPrice=proposal.stop_price,
                account=account,
                tif="GTC",
                orderRef=f"clearfills:stop:{attestation_id[:16]}",
                transmit=(proposal.target_price is None),
            )
            orders.append(stop)
        if proposal.target_price is not None:
            tp = LimitOrder(exit_action, proposal.quantity, proposal.target_price)
            tp.account = account
            tp.tif = "GTC"
            tp.orderRef = f"clearfills:tp:{attestation_id[:16]}"
            tp.transmit = True
            orders.append(tp)
        return contract, orders

    def submit_attested_order(
        self,
        proposal: TradeProposal,
        attestation: SignedAttestation,
    ) -> ExecutionReceipt:
        """Verify Ed25519 single-use attestation and route the order to IBKR (Paper or Live)."""
        # 1. Fail-closed cryptographic attestation check (single-use, 120s TTL, exact binding)
        if not self.runtime.verify_dispatch(attestation=attestation, proposal=proposal):
            raise LiveExecutionSafetyError(
                "Dispatch rejected by clearfills-firewall: invalid, expired, replayed, or mismatched Ed25519 attestation."
            )

        # 2. Verify IBKR connection & live/paper account identity
        account = self.connect()
        ib = self._get_client()

        contract, orders = self._build_contract_and_orders(
            proposal=proposal,
            account=account,
            attestation_id=attestation.attestation_id,
        )
        qualified = ib.qualifyContracts(contract)
        if qualified:
            contract = qualified[0]

        order_ids: list[int] = []
        parent_id: int | None = None
        for idx, order in enumerate(orders):
            if idx > 0 and parent_id is not None:
                if isinstance(order, dict):
                    order["parentId"] = parent_id
                else:
                    order.parentId = parent_id
            trade = ib.placeOrder(contract, order)
            oid = int(getattr(getattr(trade, "order", None), "orderId", idx + 1))
            if idx == 0:
                parent_id = oid
            order_ids.append(oid)

        return ExecutionReceipt(
            execution_mode=self._mode,
            venue="ibkr",
            symbol=proposal.symbol.upper(),
            side=proposal.side.value,
            quantity=proposal.quantity,
            order_type=proposal.order_type.value,
            limit_price=proposal.limit_price,
            stop_price=proposal.stop_price,
            target_price=proposal.target_price,
            order_ids=order_ids,
            attestation_id=attestation.attestation_id,
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
