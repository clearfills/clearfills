"""Core Pydantic v2 data models for the ClearFills Pre-Trade Risk Firewall."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class Side(str, Enum):
    BUY = "BUY"
    SELL = "SELL"


class OrderType(str, Enum):
    MARKET = "MARKET"
    LIMIT = "LIMIT"
    STOP = "STOP"
    STOP_LIMIT = "STOP_LIMIT"


class VenueType(str, Enum):
    EQUITY = "EQUITY"
    OPTIONS = "OPTIONS"
    CRYPTO = "CRYPTO"
    PREDICTION_MARKET = "PREDICTION_MARKET"
    FUTURES = "FUTURES"


class DecisionStatus(str, Enum):
    APPROVED = "APPROVED"
    VETOED = "VETOED"


class TradeProposal(BaseModel):
    """Normalized pre-trade proposal emitted by any AI agent or strategy."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(default_factory=lambda: f"prop_{uuid4().hex[:16]}")
    agent_id: str = Field(..., min_length=1, description="Identifier of the proposing AI agent")
    venue: str = Field(..., min_length=1, description="Target execution venue (e.g. ibkr, alpaca, polymarket)")
    venue_type: VenueType = Field(default=VenueType.EQUITY)
    symbol: str = Field(..., min_length=1, description="Ticker, contract, or market identifier")
    side: Side
    order_type: OrderType = Field(default=OrderType.LIMIT)
    quantity: float = Field(..., gt=0.0, description="Order quantity in shares/contracts/units")
    limit_price: Optional[float] = Field(default=None, gt=0.0, description="Limit or reference entry price")
    stop_price: Optional[float] = Field(default=None, gt=0.0, description="Protective stop-loss price")
    target_price: Optional[float] = Field(default=None, gt=0.0, description="Take-profit target price")
    reasoning_trace: str = Field(default="", description="Agent reasoning / thesis trace")
    source_citations: list[str] = Field(default_factory=list, description="Evidence URLs or document references")
    confidence: float = Field(default=0.55, ge=0.0, le=1.0, description="Agent win-probability confidence [0, 1]")
    strategy_id: str = Field(default="default", min_length=1)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("venue")
    @classmethod
    def _normalize_venue(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("symbol")
    @classmethod
    def _normalize_symbol(cls, v: str) -> str:
        return v.strip().upper()


class Position(BaseModel):
    """Open portfolio position used for exposure, heat, and short-sale checks."""

    model_config = ConfigDict(extra="forbid")

    symbol: str = Field(..., min_length=1)
    venue: str = Field(..., min_length=1)
    venue_type: VenueType = Field(default=VenueType.EQUITY)
    quantity: float = Field(..., description="Signed quantity (>0 long, <0 short)")
    avg_entry_price: float = Field(..., gt=0.0)
    current_price: float = Field(..., gt=0.0)
    stop_price: Optional[float] = Field(default=None, gt=0.0)
    unrealized_pnl_usd: float = Field(default=0.0)

    @field_validator("venue")
    @classmethod
    def _normalize_venue(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("symbol")
    @classmethod
    def _normalize_symbol(cls, v: str) -> str:
        return v.strip().upper()

    @property
    def market_value_usd(self) -> float:
        return abs(self.quantity) * self.current_price

    @property
    def risk_usd(self) -> float:
        """Open position risk to stop (or full notional for unstopped/binary positions)."""
        if self.stop_price is not None:
            return abs(self.current_price - self.stop_price) * abs(self.quantity)
        if self.venue_type == VenueType.PREDICTION_MARKET:
            return abs(self.quantity) * self.current_price
        # Conservative fallback: 10% of position value if no stop recorded
        return self.market_value_usd * 0.10


class LossSaleRecord(BaseModel):
    """Historical realized-loss sale record used for 61-day (±30d) wash-sale enforcement."""

    model_config = ConfigDict(extra="forbid")

    symbol: str = Field(..., min_length=1, description="Ticker or security identifier sold at a loss")
    sold_at: datetime = Field(..., description="Timestamp when the loss sale occurred")
    realized_loss_usd: float = Field(default=0.0, description="Realized capital loss in USD")
    account_id: str = Field(default="", description="Account identifier where the loss sale occurred")

    @field_validator("symbol")
    @classmethod
    def _normalize_symbol(cls, v: str) -> str:
        return v.strip().upper()


class PortfolioSnapshot(BaseModel):
    """Point-in-time portfolio state passed into deterministic risk evaluation."""

    model_config = ConfigDict(extra="forbid")

    account_id: str = Field(default="DU0000000", min_length=1)
    nav_usd: float = Field(..., gt=0.0, description="Net asset value in USD")
    cash_usd: float = Field(..., ge=0.0, description="Available cash in USD")
    daily_pnl_usd: float = Field(default=0.0, description="Realized + unrealized P&L for current trading day")
    session_entries: int = Field(default=0, ge=0, description="New entry orders already executed in current session")
    open_positions: list[Position] = Field(default_factory=list)
    recent_loss_sales: list[LossSaleRecord] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)

    @property
    def gross_exposure_usd(self) -> float:
        return sum(pos.market_value_usd for pos in self.open_positions if pos.quantity != 0)

    @property
    def gross_exposure_pct(self) -> float:
        return (self.gross_exposure_usd / self.nav_usd) * 100.0

    @property
    def open_position_count(self) -> int:
        return sum(1 for pos in self.open_positions if pos.quantity != 0)

    @property
    def daily_loss_pct(self) -> float:
        if self.daily_pnl_usd >= 0:
            return 0.0
        return (abs(self.daily_pnl_usd) / self.nav_usd) * 100.0

    @property
    def current_heat_usd(self) -> float:
        return sum(pos.risk_usd for pos in self.open_positions if pos.quantity != 0)

    @property
    def current_heat_pct(self) -> float:
        return (self.current_heat_usd / self.nav_usd) * 100.0

    @property
    def prediction_market_exposure_usd(self) -> float:
        return sum(
            pos.market_value_usd
            for pos in self.open_positions
            if pos.quantity != 0
            and (pos.venue_type == VenueType.PREDICTION_MARKET or pos.venue in {"polymarket", "kalshi"})
        )

    @property
    def prediction_market_exposure_pct(self) -> float:
        return (self.prediction_market_exposure_usd / self.nav_usd) * 100.0

    def held_quantity(self, symbol: str) -> float:
        sym = symbol.strip().upper()
        return sum(pos.quantity for pos in self.open_positions if pos.symbol == sym)

    def held_notional_usd(self, symbol: str) -> float:
        sym = symbol.strip().upper()
        return sum(pos.market_value_usd for pos in self.open_positions if pos.symbol == sym and pos.quantity != 0)


class SignedAttestation(BaseModel):
    """Single-use, exact-order-hash bound, TTL-enforced Ed25519 approval token."""

    model_config = ConfigDict(extra="forbid")

    attestation_id: str = Field(default_factory=lambda: f"att_{uuid4().hex[:16]}")
    nonce: str = Field(..., min_length=16)
    proposal_id: str
    agent_id: str
    order_hash: str = Field(..., min_length=64, max_length=64)
    issued_at: datetime
    expires_at: datetime
    key_id: str
    signature_b64: str


class RiskDecision(BaseModel):
    """Deterministic output of the ClearFills pre-trade risk firewall."""

    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(default_factory=lambda: f"dec_{uuid4().hex[:16]}")
    proposal_id: str
    status: DecisionStatus
    approved: bool
    reason_codes: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    attestation: Optional[SignedAttestation] = None
    evaluated_at: datetime = Field(default_factory=utc_now)


class ExecutionReceipt(BaseModel):
    """Venue execution confirmation linked back to a consumed attestation."""

    model_config = ConfigDict(extra="forbid")

    receipt_id: str = Field(default_factory=lambda: f"rcpt_{uuid4().hex[:16]}")
    attestation_id: str
    proposal_id: str
    venue: str
    venue_order_id: str
    status: str
    filled_quantity: float = Field(ge=0.0)
    avg_fill_price: Optional[float] = Field(default=None, gt=0.0)
    executed_at: datetime = Field(default_factory=utc_now)


class AuditEntry(BaseModel):
    """Single tamper-evident entry in the SHA-256 hash-chained & Ed25519-signed audit ledger."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(..., ge=1)
    timestamp: datetime
    event_type: str = Field(..., min_length=1)
    actor: str = Field(..., min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = Field(..., min_length=64, max_length=64)
    entry_hash: str = Field(..., min_length=64, max_length=64)
    entry_signature: Optional[str] = Field(default=None)
    signer_key_id: Optional[str] = Field(default=None)

    @property
    def seq_no(self) -> int:
        """Monotonic sequence number alias (1, 2, 3...)."""
        return self.seq
