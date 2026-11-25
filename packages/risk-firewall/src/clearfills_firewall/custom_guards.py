"""Extensible custom pre-trade guards (Python plugins & safe zero-eval declarative rules)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from .models import PortfolioSnapshot, TradeProposal


class GuardViolation(BaseModel):
    """Structured rejection returned by a user-defined Python or declarative guard."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., min_length=1, max_length=96)
    reason: str = Field(..., min_length=1, max_length=1000)
    guard_name: str = Field(default="custom", min_length=1, max_length=96)


CustomGuardReturn = Union[GuardViolation, list[GuardViolation], None]
CustomGuardFn = Callable[[TradeProposal, PortfolioSnapshot], CustomGuardReturn]


class DeclarativeGuardRule(BaseModel):
    """Pure-data, zero-eval custom guard rule safe for AI agents to draft and humans to approve."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=1, max_length=96)
    name: str = Field(..., min_length=1, max_length=128)
    enabled: bool = True
    symbols: list[str] = Field(default_factory=list)
    sides: list[str] = Field(default_factory=list)
    order_types: list[str] = Field(default_factory=list)
    max_notional_usd: Optional[float] = Field(default=None, gt=0.0)
    max_nav_pct: Optional[float] = Field(default=None, gt=0.0, le=100.0)
    blackout_dates: list[str] = Field(default_factory=list)
    block_always: bool = False
    code: str = Field(default="CUSTOM_RULE_VIOLATION", min_length=1, max_length=96)
    reason: str = Field(default="Blocked by custom declarative guard rule.", min_length=1, max_length=1000)


def evaluate_declarative_rule(
    rule: DeclarativeGuardRule,
    proposal: TradeProposal,
    portfolio: PortfolioSnapshot,
    *,
    today_utc: Optional[str] = None,
) -> Optional[GuardViolation]:
    """Deterministically evaluate a DeclarativeGuardRule with zero dynamic code execution."""
    if not rule.enabled:
        return None

    sym = proposal.symbol.strip().upper()
    if rule.symbols:
        allowed_syms = {s.strip().upper() for s in rule.symbols if s.strip()}
        if sym not in allowed_syms:
            return None

    if rule.sides:
        allowed_sides = {s.strip().upper() for s in rule.sides if s.strip()}
        if proposal.side.value.upper() not in allowed_sides:
            return None

    if rule.order_types:
        allowed_types = {t.strip().upper() for t in rule.order_types if t.strip()}
        if proposal.order_type.value.upper() not in allowed_types:
            return None

    notional = abs(float(proposal.quantity) * float(proposal.limit_price))
    current_date = today_utc or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if rule.block_always:
        return GuardViolation(code=rule.code, reason=rule.reason, guard_name=rule.name)

    if rule.blackout_dates:
        blackouts = {d.strip() for d in rule.blackout_dates if d.strip()}
        if current_date in blackouts:
            return GuardViolation(
                code=rule.code,
                reason=f"{rule.reason} (blackout date {current_date})",
                guard_name=rule.name,
            )

    if rule.max_notional_usd is not None and notional > rule.max_notional_usd:
        return GuardViolation(
            code=rule.code,
            reason=f"{rule.reason} (notional ${notional:,.2f} > cap ${rule.max_notional_usd:,.2f})",
            guard_name=rule.name,
        )

    if rule.max_nav_pct is not None and portfolio.nav_usd > 0:
        pct = (notional / portfolio.nav_usd) * 100.0
        if pct > rule.max_nav_pct:
            return GuardViolation(
                code=rule.code,
                reason=f"{rule.reason} ({pct:.2f}% NAV > cap {rule.max_nav_pct:.2f}%)",
                guard_name=rule.name,
            )

    return None
