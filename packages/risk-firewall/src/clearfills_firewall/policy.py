"""Deterministic YAML-configurable pre-trade risk policy & evaluator."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

import yaml
from pydantic import BaseModel, ConfigDict, Field

_ET = ZoneInfo("America/New_York")

from .killswitch import KillSwitch
from .models import (
    DecisionStatus,
    PortfolioSnapshot,
    RiskDecision,
    Side,
    TradeProposal,
    VenueType,
    utc_now,
)


class RiskPolicy(BaseModel):
    """Deterministic pre-trade risk policy loaded from YAML or code."""

    model_config = ConfigDict(extra="forbid")

    policy_version: str = Field(default="1.0.0")
    max_risk_per_trade_pct: float = Field(default=1.0, gt=0.0, le=100.0)
    max_open_positions: int = Field(default=10, ge=1)
    max_total_heat_pct: float = Field(default=8.0, gt=0.0, le=100.0)
    max_daily_loss_pct: float = Field(default=2.0, gt=0.0, le=100.0)
    require_stop_loss: bool = Field(default=True)
    max_order_notional_usd: float = Field(default=50_000.0, gt=0.0)
    allowed_venues: list[str] = Field(
        default_factory=lambda: ["ibkr", "alpaca", "polymarket", "kalshi", "paper"]
    )
    blocked_symbols: list[str] = Field(default_factory=list)
    allow_shorting: bool = Field(default=False)
    max_prediction_market_exposure_pct: float = Field(default=15.0, ge=0.0, le=100.0)
    fractional_kelly_multiplier: float = Field(default=0.25, gt=0.0, le=1.0)
    enforce_kelly_sizing: bool = Field(default=True)
    max_entries_per_session: Optional[int] = Field(default=None, ge=1)
    block_last_session_of_week: bool = Field(default=False)
    no_entries_after_et: Optional[str] = Field(default=None)
    max_gross_exposure_pct: Optional[float] = Field(default=None, gt=0.0, le=500.0)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RiskPolicy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise ValueError("RiskPolicy YAML must be a mapping at top level")
        return cls.model_validate(raw)

    def to_yaml(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            yaml.safe_dump(self.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )


def _is_prediction_market(proposal: TradeProposal) -> bool:
    return (
        proposal.venue_type == VenueType.PREDICTION_MARKET
        or proposal.venue.lower() in {"polymarket", "kalshi"}
    )


def evaluate_proposal(
    proposal: TradeProposal,
    portfolio: PortfolioSnapshot,
    policy: RiskPolicy,
    kill_switch: KillSwitch,
) -> RiskDecision:
    """Deterministically evaluate a trade proposal against policy, portfolio, and kill switch.

    Accumulates all violations with exact reason codes so callers and auditors receive
    complete diagnostic visibility. Never relies on LLM judgement.
    """
    reason_codes: list[str] = []
    reasons: list[str] = []
    metrics: dict[str, Any] = {
        "policy_version": policy.policy_version,
        "nav_usd": portfolio.nav_usd,
        "cash_usd": portfolio.cash_usd,
        "open_position_count": portfolio.open_position_count,
        "daily_loss_pct": round(portfolio.daily_loss_pct, 4),
        "current_heat_pct": round(portfolio.current_heat_pct, 4),
    }

    def add_veto(code: str, message: str) -> None:
        reason_codes.append(code)
        reasons.append(message)

    # 1. Fail-closed Kill Switch check
    ks_state = kill_switch.status()
    if ks_state.tripped:
        if ks_state.corrupt_or_missing:
            add_veto("KILL_SWITCH_FAIL_CLOSED", ks_state.reason)
        else:
            add_veto(
                "KILL_SWITCH_TRIPPED",
                f"Kill switch is tripped by {ks_state.actor}: {ks_state.reason}",
            )

    # 2. Venue allowlist check
    allowed_venues = {v.strip().lower() for v in policy.allowed_venues}
    if proposal.venue.lower() not in allowed_venues:
        add_veto(
            "VENUE_NOT_ALLOWED",
            f"Venue '{proposal.venue}' is not in allowed_venues {sorted(allowed_venues)}",
        )

    # 3. Blocked symbol check
    blocked_symbols = {s.strip().upper() for s in policy.blocked_symbols}
    if proposal.symbol.upper() in blocked_symbols:
        add_veto(
            "SYMBOL_BLOCKED",
            f"Symbol '{proposal.symbol}' is explicitly blocked by policy",
        )

    # 4. Shorting check
    held_qty = portfolio.held_quantity(proposal.symbol)
    is_reducing_position = proposal.side == Side.SELL and held_qty >= proposal.quantity
    if proposal.side == Side.SELL and not policy.allow_shorting and held_qty < proposal.quantity:
        add_veto(
            "SHORTING_NOT_ALLOWED",
            f"SELL quantity {proposal.quantity} exceeds held long quantity {held_qty} and allow_shorting=False",
        )

    # 5. Daily loss circuit breaker
    if portfolio.daily_loss_pct >= policy.max_daily_loss_pct:
        add_veto(
            "DAILY_LOSS_LIMIT_BREACHED",
            f"Daily loss {portfolio.daily_loss_pct:.2f}% >= max_daily_loss_pct {policy.max_daily_loss_pct:.2f}%",
        )

    # 6. Max open positions (only applies when opening a new symbol exposure)
    if held_qty == 0 and portfolio.open_position_count >= policy.max_open_positions:
        add_veto(
            "MAX_OPEN_POSITIONS_EXCEEDED",
            f"Open positions ({portfolio.open_position_count}) already at max_open_positions ({policy.max_open_positions})",
        )

    # 6b. Session entry caps & calendar/time-of-day cutoffs (never block closing/reducing orders)
    if not is_reducing_position:
        if (
            policy.max_entries_per_session is not None
            and portfolio.session_entries >= policy.max_entries_per_session
        ):
            add_veto(
                "MAX_ENTRIES_PER_SESSION_EXCEEDED",
                f"Session entries ({portfolio.session_entries}) already at max_entries_per_session ({policy.max_entries_per_session})",
            )

        eval_et = proposal.created_at.astimezone(_ET)
        if policy.block_last_session_of_week and eval_et.weekday() == 4:
            add_veto(
                "LAST_SESSION_OF_WEEK_BLOCKED",
                "Policy blocks new entries on the last session of the week (Friday ET)",
            )

        if policy.no_entries_after_et:
            try:
                cutoff_h, cutoff_m = (int(x) for x in policy.no_entries_after_et.strip().split(":", 1))
                if (eval_et.hour, eval_et.minute) >= (cutoff_h, cutoff_m):
                    add_veto(
                        "SESSION_CUTOFF_EXCEEDED",
                        f"Order time {eval_et.strftime('%H:%M')} ET is at or after no_entries_after_et ({policy.no_entries_after_et} ET)",
                    )
            except ValueError:
                pass

    # 7. Reference / entry price required for deterministic sizing
    entry_price: Optional[float] = proposal.limit_price
    if entry_price is None or entry_price <= 0:
        add_veto(
            "MISSING_REFERENCE_PRICE",
            "Proposal must specify a positive limit_price for deterministic notional and risk sizing",
        )
    else:
        order_notional_usd = proposal.quantity * entry_price
        metrics["entry_price"] = entry_price
        metrics["order_notional_usd"] = round(order_notional_usd, 4)

        # 8. Max order notional cap
        if order_notional_usd > policy.max_order_notional_usd:
            add_veto(
                "MAX_ORDER_NOTIONAL_EXCEEDED",
                f"Order notional ${order_notional_usd:,.2f} exceeds max_order_notional_usd ${policy.max_order_notional_usd:,.2f}",
            )

        # 8b. Max gross exposure cap (for new/expanding positions)
        if policy.max_gross_exposure_pct is not None and not is_reducing_position:
            projected_gross_pct = ((portfolio.gross_exposure_usd + order_notional_usd) / portfolio.nav_usd) * 100.0
            metrics["projected_gross_exposure_pct"] = round(projected_gross_pct, 4)
            if projected_gross_pct > policy.max_gross_exposure_pct:
                add_veto(
                    "MAX_GROSS_EXPOSURE_EXCEEDED",
                    f"Projected gross exposure {projected_gross_pct:.2f}% exceeds max_gross_exposure_pct {policy.max_gross_exposure_pct:.2f}%",
                )

        # 9. Stop-loss validation & stop-distance risk computation
        is_pm = _is_prediction_market(proposal)
        stop_distance: Optional[float] = None

        if proposal.stop_price is not None:
            if proposal.side == Side.BUY and proposal.stop_price >= entry_price:
                add_veto(
                    "INVALID_STOP_LOSS_DIRECTION",
                    f"BUY stop_price ({proposal.stop_price}) must be strictly below entry_price ({entry_price})",
                )
            elif proposal.side == Side.SELL and proposal.stop_price <= entry_price:
                add_veto(
                    "INVALID_STOP_LOSS_DIRECTION",
                    f"SELL stop_price ({proposal.stop_price}) must be strictly above entry_price ({entry_price})",
                )
            else:
                stop_distance = abs(entry_price - proposal.stop_price)
        elif policy.require_stop_loss and not is_pm and not is_reducing_position:
            add_veto(
                "MISSING_STOP_LOSS",
                "Policy requires a protective stop_price on all new non-prediction-market orders",
            )
        elif is_pm:
            # Binary prediction market contracts have bounded downside = entry_price per contract (for BUY)
            stop_distance = entry_price if proposal.side == Side.BUY else max(0.0, 1.0 - entry_price)

        if stop_distance is not None and stop_distance > 0:
            trade_risk_usd = stop_distance * proposal.quantity
            trade_risk_pct = (trade_risk_usd / portfolio.nav_usd) * 100.0
            max_risk_usd = portfolio.nav_usd * (policy.max_risk_per_trade_pct / 100.0)
            max_qty_by_risk = max_risk_usd / stop_distance
            projected_heat_pct = portfolio.current_heat_pct + trade_risk_pct

            metrics["stop_distance"] = round(stop_distance, 6)
            metrics["trade_risk_usd"] = round(trade_risk_usd, 4)
            metrics["trade_risk_pct"] = round(trade_risk_pct, 4)
            metrics["max_qty_by_risk"] = round(max_qty_by_risk, 4)
            metrics["projected_heat_pct"] = round(projected_heat_pct, 4)

            # 10. Per-trade risk cap
            if trade_risk_pct > policy.max_risk_per_trade_pct:
                add_veto(
                    "MAX_RISK_PER_TRADE_EXCEEDED",
                    f"Trade risk {trade_risk_pct:.2f}% (${trade_risk_usd:,.2f}) exceeds max_risk_per_trade_pct {policy.max_risk_per_trade_pct:.2f}% (max qty {max_qty_by_risk:.2f})",
                )

            # 11. Total portfolio heat cap
            if projected_heat_pct > policy.max_total_heat_pct:
                add_veto(
                    "MAX_TOTAL_HEAT_EXCEEDED",
                    f"Projected portfolio heat {projected_heat_pct:.2f}% exceeds max_total_heat_pct {policy.max_total_heat_pct:.2f}%",
                )

            # 12. Fractional-Kelly sizing check when target_price is supplied
            if proposal.target_price is not None:
                valid_target = (
                    (proposal.side == Side.BUY and proposal.target_price > entry_price)
                    or (proposal.side == Side.SELL and proposal.target_price < entry_price)
                )
                if not valid_target:
                    add_veto(
                        "INVALID_TARGET_DIRECTION",
                        f"target_price ({proposal.target_price}) is on the wrong side of entry_price ({entry_price}) for {proposal.side.value}",
                    )
                else:
                    reward_distance = abs(proposal.target_price - entry_price)
                    payoff_ratio = reward_distance / stop_distance  # b
                    p = proposal.confidence
                    q = 1.0 - p
                    full_kelly = (p * payoff_ratio - q) / payoff_ratio
                    fractional_kelly = max(0.0, full_kelly * policy.fractional_kelly_multiplier)
                    kelly_risk_cap_pct = fractional_kelly * 100.0
                    kelly_max_qty = (portfolio.nav_usd * fractional_kelly) / stop_distance

                    metrics["payoff_ratio"] = round(payoff_ratio, 4)
                    metrics["full_kelly_fraction"] = round(full_kelly, 4)
                    metrics["fractional_kelly_pct"] = round(kelly_risk_cap_pct, 4)
                    metrics["max_qty_by_kelly"] = round(kelly_max_qty, 4)

                    if policy.enforce_kelly_sizing:
                        if full_kelly <= 0.0:
                            add_veto(
                                "NEGATIVE_KELLY_EDGE",
                                f"Negative Kelly edge ({full_kelly:.4f}) for confidence={p:.2f} and R:R={payoff_ratio:.2f}",
                            )
                        elif trade_risk_pct > kelly_risk_cap_pct:
                            add_veto(
                                "KELLY_POSITION_SIZE_EXCEEDED",
                                f"Trade risk {trade_risk_pct:.2f}% exceeds fractional-Kelly cap {kelly_risk_cap_pct:.2f}% (max qty {kelly_max_qty:.2f})",
                            )

        # 13. Prediction market exposure cap
        if is_pm:
            projected_pm_usd = portfolio.prediction_market_exposure_usd + order_notional_usd
            projected_pm_pct = (projected_pm_usd / portfolio.nav_usd) * 100.0
            metrics["projected_prediction_market_exposure_pct"] = round(projected_pm_pct, 4)
            if projected_pm_pct > policy.max_prediction_market_exposure_pct:
                add_veto(
                    "MAX_PREDICTION_MARKET_EXPOSURE_EXCEEDED",
                    f"Projected prediction-market exposure {projected_pm_pct:.2f}% exceeds max_prediction_market_exposure_pct {policy.max_prediction_market_exposure_pct:.2f}%",
                )

    approved = len(reason_codes) == 0
    return RiskDecision(
        proposal_id=proposal.proposal_id,
        status=DecisionStatus.APPROVED if approved else DecisionStatus.VETOED,
        approved=approved,
        reason_codes=reason_codes,
        reasons=reasons,
        metrics=metrics,
        evaluated_at=utc_now(),
    )
