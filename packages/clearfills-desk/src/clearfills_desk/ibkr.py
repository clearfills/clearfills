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

from clearfills_firewall import OrderType, Side, SignedAttestation, TradeProposal

from .runtime import DeskRuntime, IBKRConnectionConfig

PAPER_PORTS: frozenset[int] = frozenset({4002, 7497})
LIVE_PORTS: frozenset[int] = frozenset({4001, 7496})
PAPER_PREFIX = "DU"
LIVE_ENV_FLAG = "CLEARFILLS_ALLOW_LIVE"
_TAILSCALE_CGNAT = ipaddress.ip_network("100.64.0.0/10")


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
        if cfg.port not in PAPER_PORTS:
            raise LiveExecutionSafetyError(
                f"Paper mode refuses port {cfg.port}; allowed paper ports: {sorted(PAPER_PORTS)}."
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

    def connect(self) -> str:
        """Connect to IBKR Gateway/TWS and verify the active account matches mode."""
        cfg = self.runtime.config.ibkr
        validate_ibkr_connection(cfg, self._mode, env=self._env)
        ib = self._get_client()
        if not ib.isConnected():
            ib.connect(cfg.host, cfg.port, clientId=cfg.client_id, readonly=False)
        return verify_connected_accounts(ib.managedAccounts(), cfg.account_id, self._mode)

    def disconnect(self) -> None:
        if self._ib is not None and self._ib.isConnected():
            self._ib.disconnect()

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
