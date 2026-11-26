"""Trusted server-side PortfolioProvider implementations.

Prevents untrusted AI agents from spoofing NAV, cash balance, open positions,
or daily P&L in `propose_trade` calls by sourcing portfolio state authoritatively
on the firewall server side with snapshot freshness enforcement.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Callable, Optional, Protocol, runtime_checkable

from .models import PortfolioSnapshot, Position, Side, VenueType, utc_now


@runtime_checkable
class PortfolioProvider(Protocol):
    """Protocol for server-side authoritative portfolio snapshot providers."""

    def get_snapshot(self, account_id: Optional[str] = None) -> PortfolioSnapshot:
        """Return an authoritative, timestamped PortfolioSnapshot."""
        ...


class StaticTrustedPortfolioProvider:
    """In-memory trusted portfolio provider backed by a server-controlled snapshot."""

    def __init__(
        self,
        snapshot: PortfolioSnapshot,
        *,
        clock: Callable[[], datetime] = utc_now,
        refresh_timestamp: bool = False,
    ) -> None:
        self._lock = threading.Lock()
        self._snapshot = snapshot.model_copy(deep=True)
        self._clock = clock
        self._refresh_timestamp = refresh_timestamp

    def update_snapshot(self, snapshot: PortfolioSnapshot) -> None:
        """Replace the authoritative server-side snapshot."""
        with self._lock:
            self._snapshot = snapshot.model_copy(deep=True)

    def get_snapshot(self, account_id: Optional[str] = None) -> PortfolioSnapshot:
        with self._lock:
            snap = self._snapshot.model_copy(deep=True)
            if self._refresh_timestamp:
                snap = snap.model_copy(update={"timestamp": self._clock()})
            return snap


class SimulatedPaperPortfolioProvider:
    """Authoritative paper-trading portfolio provider with server-side fill accounting."""

    def __init__(
        self,
        *,
        account_id: str = "PAPER-001",
        nav_usd: float = 100_000.0,
        cash_usd: Optional[float] = None,
        daily_pnl_usd: float = 0.0,
        session_entries: int = 0,
        open_positions: Optional[list[Position]] = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._lock = threading.Lock()
        self._account_id = account_id
        self._positions: list[Position] = [p.model_copy(deep=True) for p in (open_positions or [])]
        positions_val = sum(p.market_value_usd for p in self._positions if p.quantity != 0)
        self._cash_usd = float(cash_usd) if cash_usd is not None else max(0.0, float(nav_usd) - positions_val)
        self._nav_usd = float(nav_usd)
        self._daily_pnl_usd = float(daily_pnl_usd)
        self._session_entries = int(session_entries)
        self._clock = clock

    def get_snapshot(self, account_id: Optional[str] = None) -> PortfolioSnapshot:
        with self._lock:
            positions_copy = [p.model_copy(deep=True) for p in self._positions if p.quantity != 0]
            positions_val = sum(p.market_value_usd for p in positions_copy)
            nav = max(1e-6, self._cash_usd + positions_val) if positions_copy else self._nav_usd
            return PortfolioSnapshot(
                account_id=account_id or self._account_id,
                nav_usd=nav,
                cash_usd=max(0.0, self._cash_usd),
                daily_pnl_usd=self._daily_pnl_usd,
                session_entries=self._session_entries,
                open_positions=positions_copy,
                timestamp=self._clock(),
            )

    def record_fill(
        self,
        *,
        symbol: str,
        venue: str,
        side: Side,
        quantity: float,
        price: float,
        stop_price: Optional[float] = None,
        venue_type: VenueType = VenueType.EQUITY,
    ) -> PortfolioSnapshot:
        """Apply a filled paper order to authoritative cash, positions, and session entries."""
        sym = symbol.strip().upper()
        ven = venue.strip().lower()
        notional = quantity * price

        with self._lock:
            existing = next((p for p in self._positions if p.symbol == sym and p.venue == ven), None)
            if side == Side.BUY:
                self._cash_usd = max(0.0, self._cash_usd - notional)
                self._session_entries += 1
                if existing is not None:
                    new_qty = existing.quantity + quantity
                    if abs(new_qty) < 1e-9:
                        self._positions.remove(existing)
                    else:
                        avg_price = (
                            (existing.quantity * existing.avg_entry_price + quantity * price) / new_qty
                            if new_qty > 0
                            else price
                        )
                        existing.quantity = new_qty
                        existing.avg_entry_price = avg_price
                        existing.current_price = price
                        if stop_price is not None:
                            existing.stop_price = stop_price
                else:
                    self._positions.append(
                        Position(
                            symbol=sym,
                            venue=ven,
                            venue_type=venue_type,
                            quantity=quantity,
                            avg_entry_price=price,
                            current_price=price,
                            stop_price=stop_price,
                        )
                    )
            else:
                self._cash_usd += notional
                if existing is not None:
                    realized = (price - existing.avg_entry_price) * min(quantity, max(0.0, existing.quantity))
                    self._daily_pnl_usd += realized
                    new_qty = existing.quantity - quantity
                    if abs(new_qty) < 1e-9:
                        self._positions.remove(existing)
                    else:
                        existing.quantity = new_qty
                        existing.current_price = price
                else:
                    self._positions.append(
                        Position(
                            symbol=sym,
                            venue=ven,
                            venue_type=venue_type,
                            quantity=-quantity,
                            avg_entry_price=price,
                            current_price=price,
                            stop_price=stop_price,
                        )
                    )
            positions_val = sum(p.market_value_usd for p in self._positions if p.quantity != 0)
            self._nav_usd = max(1e-6, self._cash_usd + positions_val)
        return self.get_snapshot()
