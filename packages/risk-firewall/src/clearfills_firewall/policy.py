"""Deterministic YAML-configurable pre-trade risk policy & evaluator."""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from zoneinfo import ZoneInfo

import yaml
from pydantic import BaseModel, ConfigDict, Field

_ET = ZoneInfo("America/New_York")

from .killswitch import KillSwitch
from .models import (
    DecisionStatus,
    OrderType,
    PortfolioSnapshot,
    RiskDecision,
    Side,
    TradeProposal,
    VenueType,
    utc_now,
)
from .providers import PortfolioProvider


class SleevePolicy(BaseModel):
    """Per-sleeve / asset-class risk override profile (e.g., cash_equivalent, core_index).

    Fields left as None inherit the parent RiskPolicy default.
    """

    model_config = ConfigDict(extra="forbid")

    symbols: list[str] = Field(default_factory=list)
    require_stop_loss: Optional[bool] = None
    max_order_notional_usd: Optional[float] = Field(default=None, gt=0.0)
    max_risk_per_trade_pct: Optional[float] = Field(default=None, gt=0.0, le=100.0)
    max_total_heat_pct: Optional[float] = Field(default=None, gt=0.0, le=100.0)
    max_gross_exposure_pct: Optional[float] = Field(default=None, gt=0.0, le=500.0)
    max_position_concentration_pct: Optional[float] = Field(default=None, gt=0.0, le=100.0)
    max_daily_cumulative_notional_usd: Optional[float] = Field(default=None, gt=0.0)
    exempt_session_entry_cap: bool = Field(default=False)
    exempt_last_session_of_week: bool = Field(default=False)
    exempt_session_cutoff: bool = Field(default=False)
    allow_shorting: Optional[bool] = None
    allow_market_orders: Optional[bool] = None
    allow_margin: Optional[bool] = None


def default_allocation_sleeves() -> dict[str, SleevePolicy]:
    """Institutional preset sleeves for T-bill cash parking and core index ETFs."""
    return {
        "cash_equivalent": SleevePolicy(
            symbols=["SGOV", "BIL", "CBIL", "SHV", "USFR", "TFLO"],
            require_stop_loss=False,
            max_order_notional_usd=500_000.0,
            max_position_concentration_pct=100.0,
            max_daily_cumulative_notional_usd=1_000_000.0,
            exempt_session_entry_cap=True,
            exempt_last_session_of_week=True,
            exempt_session_cutoff=True,
        ),
        "core_index": SleevePolicy(
            symbols=["VT", "VTI", "VOO", "SPY", "QQQ", "VEQT", "VBAL", "XEQT", "VXUS", "BND"],
            require_stop_loss=False,
            max_order_notional_usd=500_000.0,
            max_position_concentration_pct=100.0,
            max_daily_cumulative_notional_usd=1_000_000.0,
            exempt_session_entry_cap=True,
            exempt_last_session_of_week=True,
            exempt_session_cutoff=True,
        ),
    }


class RiskPolicy(BaseModel):
    """Deterministic pre-trade risk policy loaded from YAML or code."""

    model_config = ConfigDict(extra="forbid")

    policy_version: str = Field(default="1.0.0")
    max_risk_per_trade_pct: float = Field(default=1.5, gt=0.0, le=100.0)
    max_open_positions: int = Field(default=10, ge=1)
    max_total_heat_pct: float = Field(default=8.0, gt=0.0, le=100.0)
    max_daily_loss_pct: float = Field(default=3.0, gt=0.0, le=100.0)
    require_stop_loss: bool = Field(default=True)
    max_order_notional_usd: float = Field(default=50_000.0, gt=0.0)
    max_position_concentration_pct: float = Field(default=20.0, gt=0.0, le=100.0)
    max_daily_cumulative_notional_usd: float = Field(default=200_000.0, gt=0.0)
    max_orders_per_minute: int = Field(default=10, ge=1)
    max_snapshot_age_seconds: float = Field(default=30.0, gt=0.0)
    allowed_venues: list[str] = Field(
        default_factory=lambda: ["ibkr", "alpaca", "polymarket", "kalshi", "paper"]
    )
    blocked_symbols: list[str] = Field(default_factory=list)
    allow_shorting: bool = Field(default=False)
    allow_market_orders: bool = Field(default=False)
    allow_margin: bool = Field(default=False)
    max_prediction_market_exposure_pct: float = Field(default=15.0, ge=0.0, le=100.0)
    fractional_kelly_multiplier: float = Field(default=0.25, gt=0.0, le=1.0)
    max_kelly_confidence: float = Field(default=0.75, gt=0.0, le=1.0)
    enforce_kelly_sizing: bool = Field(default=True)
    enforce_trusted_kelly: bool = Field(default=True)
    max_entries_per_session: Optional[int] = Field(default=None, ge=1)
    block_last_session_of_week: bool = Field(default=False)
    no_entries_after_et: Optional[str] = Field(default=None)
    max_gross_exposure_pct: Optional[float] = Field(default=None, gt=0.0, le=500.0)
    sleeves: dict[str, SleevePolicy] = Field(default_factory=dict)
    is_us_tax_person: bool = Field(default=False)
    pfic_symbols: list[str] = Field(
        default_factory=lambda: [
            "VEQT",
            "XEQT",
            "VBAL",
            "VGRO",
            "CBIL",
            "CASH",
            "PSA",
            "HSAV",
            "ZAG",
            "XIC",
            "VFV",
            "XIU",
            "DLR",
        ]
    )
    recent_loss_sale_symbols: list[str] = Field(default_factory=list)
    wash_sale_restricted_symbols: list[str] = Field(default_factory=list)
    insider_blackout_windows: list[dict[str, str]] = Field(default_factory=list)

    def resolve_sleeve(self, symbol: str) -> tuple[str, Optional[SleevePolicy]]:
        """Return (sleeve_name, SleevePolicy) matching symbol, or ('active_trading', None)."""
        sym = symbol.strip().upper()
        for name, sleeve in self.sleeves.items():
            if sym in {s.strip().upper() for s in sleeve.symbols}:
                return name, sleeve
        return "active_trading", None

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


def _compute_effective_portfolio_heat_pct(
    portfolio: PortfolioSnapshot,
    policy: RiskPolicy,
) -> float:
    """Compute portfolio stop-loss heat while respecting stop-exempt sleeves (e.g. SGOV/VOO)."""
    total_risk_usd = 0.0
    for pos in portfolio.open_positions:
        if pos.quantity == 0:
            continue
        if pos.stop_price is not None:
            total_risk_usd += abs(pos.current_price - pos.stop_price) * abs(pos.quantity)
        elif pos.venue_type == VenueType.PREDICTION_MARKET or pos.venue in {"polymarket", "kalshi"}:
            total_risk_usd += abs(pos.quantity) * pos.current_price
        else:
            _, pos_sleeve = policy.resolve_sleeve(pos.symbol)
            if pos_sleeve is not None and pos_sleeve.require_stop_loss is False:
                continue
            total_risk_usd += pos.market_value_usd * 0.10
    return (total_risk_usd / portfolio.nav_usd) * 100.0


def evaluate_proposal(
    proposal: TradeProposal,
    portfolio: PortfolioSnapshot,
    policy: RiskPolicy,
    kill_switch: KillSwitch,
    *,
    daily_cumulative_notional_usd: float = 0.0,
    recent_order_count_1m: int = 0,
) -> RiskDecision:
    """Deterministically evaluate a trade proposal against policy, portfolio, and kill switch.

    Accumulates all violations with exact reason codes so callers and auditors receive
    complete diagnostic visibility. Never relies on LLM judgement.
    """
    sleeve_name, sleeve = policy.resolve_sleeve(proposal.symbol)
    eff_require_stop = (
        sleeve.require_stop_loss
        if (sleeve is not None and sleeve.require_stop_loss is not None)
        else policy.require_stop_loss
    )
    eff_max_notional = (
        sleeve.max_order_notional_usd
        if (sleeve is not None and sleeve.max_order_notional_usd is not None)
        else policy.max_order_notional_usd
    )
    eff_max_risk_pct = (
        sleeve.max_risk_per_trade_pct
        if (sleeve is not None and sleeve.max_risk_per_trade_pct is not None)
        else policy.max_risk_per_trade_pct
    )
    eff_max_heat_pct = (
        sleeve.max_total_heat_pct
        if (sleeve is not None and sleeve.max_total_heat_pct is not None)
        else policy.max_total_heat_pct
    )
    eff_max_gross_pct = (
        sleeve.max_gross_exposure_pct
        if (sleeve is not None and sleeve.max_gross_exposure_pct is not None)
        else policy.max_gross_exposure_pct
    )
    eff_max_concentration_pct = (
        sleeve.max_position_concentration_pct
        if (sleeve is not None and sleeve.max_position_concentration_pct is not None)
        else policy.max_position_concentration_pct
    )
    eff_max_daily_cumulative_notional = (
        sleeve.max_daily_cumulative_notional_usd
        if (sleeve is not None and sleeve.max_daily_cumulative_notional_usd is not None)
        else policy.max_daily_cumulative_notional_usd
    )
    eff_allow_shorting = (
        sleeve.allow_shorting
        if (sleeve is not None and sleeve.allow_shorting is not None)
        else policy.allow_shorting
    )
    eff_allow_market_orders = (
        sleeve.allow_market_orders
        if (sleeve is not None and sleeve.allow_market_orders is not None)
        else policy.allow_market_orders
    )
    eff_allow_margin = (
        sleeve.allow_margin
        if (sleeve is not None and sleeve.allow_margin is not None)
        else policy.allow_margin
    )
    exempt_entry_cap = bool(sleeve is not None and sleeve.exempt_session_entry_cap)
    exempt_last_session = bool(sleeve is not None and sleeve.exempt_last_session_of_week)
    exempt_cutoff = bool(sleeve is not None and sleeve.exempt_session_cutoff)

    effective_heat_pct = _compute_effective_portfolio_heat_pct(portfolio, policy)

    reason_codes: list[str] = []
    reasons: list[str] = []
    metrics: dict[str, Any] = {
        "policy_version": policy.policy_version,
        "sleeve": sleeve_name,
        "nav_usd": portfolio.nav_usd,
        "cash_usd": portfolio.cash_usd,
        "open_position_count": portfolio.open_position_count,
        "daily_loss_pct": round(portfolio.daily_loss_pct, 4),
        "current_heat_pct": round(effective_heat_pct, 4),
        "raw_portfolio_heat_pct": round(portfolio.current_heat_pct, 4),
        "daily_cumulative_notional_usd": round(daily_cumulative_notional_usd, 4),
        "recent_orders_1m": recent_order_count_1m,
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
    prop_sym = proposal.symbol.strip().upper()
    blocked_symbols = {s.strip().upper() for s in policy.blocked_symbols}
    if prop_sym in blocked_symbols:
        add_veto(
            "SYMBOL_BLOCKED",
            f"Symbol '{proposal.symbol}' is explicitly blocked by policy",
        )

    # 3a. Cross-border US PFIC hard veto (IRS Form 8621)
    if policy.is_us_tax_person and proposal.side == Side.BUY:
        pfic_symbols = {s.strip().upper() for s in policy.pfic_symbols}
        if prop_sym in pfic_symbols or prop_sym.endswith(".TO"):
            add_veto(
                "PFIC_FORBIDDEN_FOR_US_PERSON",
                f"Symbol '{proposal.symbol}' is a non-US pooled fund/ETF and triggers punitive IRS Form 8621 PFIC taxation for US tax persons outside qualified retirement accounts",
            )

    # 3b-tax. IRS 30-day wash-sale / CRA superficial-loss hard veto (61-day ±30d window)
    if proposal.side == Side.BUY:
        if policy.recent_loss_sale_symbols:
            recent_loss_symbols = {s.strip().upper() for s in policy.recent_loss_sale_symbols}
            if prop_sym in recent_loss_symbols:
                add_veto(
                    "SUPERFICIAL_LOSS_BLOCKED",
                    f"Buying identical security '{proposal.symbol}' within ±30 days of a realized loss sale across affiliated entities disallows the harvested capital loss under IRS wash-sale / CRA superficial-loss rules",
                )
        if policy.wash_sale_restricted_symbols:
            restricted_syms = {s.strip().upper() for s in policy.wash_sale_restricted_symbols}
            if prop_sym in restricted_syms:
                add_veto(
                    "WASH_SALE_WINDOW_VIOLATION",
                    f"Symbol '{proposal.symbol}' is restricted under wash_sale_restricted_symbols; BUY blocked to preserve harvested capital loss",
                )
        if portfolio.recent_loss_sales:
            proposal_dt = (
                proposal.created_at.replace(tzinfo=timezone.utc)
                if proposal.created_at.tzinfo is None
                else proposal.created_at.astimezone(timezone.utc)
            )
            for sale in portfolio.recent_loss_sales:
                if sale.symbol.strip().upper() != prop_sym:
                    continue
                sold_dt = (
                    sale.sold_at.replace(tzinfo=timezone.utc)
                    if sale.sold_at.tzinfo is None
                    else sale.sold_at.astimezone(timezone.utc)
                )
                days_apart = abs((proposal_dt.date() - sold_dt.date()).days)
                if days_apart <= 30:
                    acct_label = sale.account_id or portfolio.account_id
                    add_veto(
                        "WASH_SALE_WINDOW_VIOLATION",
                        (
                            f"Buying '{proposal.symbol}' on {proposal_dt.date().isoformat()} is within the 61-day (±30d) "
                            f"wash-sale window ({days_apart} days from realized loss sale on {sold_dt.date().isoformat()} "
                            f"in account '{acct_label}', loss=${abs(sale.realized_loss_usd):,.2f})"
                        ),
                    )
                    break

    # 3c-compliance. Corporate insider / MNPI trading-window blackout veto (both BUY and SELL)
    if policy.insider_blackout_windows:
        eval_date = proposal.created_at.astimezone(_ET).date().isoformat()
        for win in policy.insider_blackout_windows:
            if not isinstance(win, dict):
                continue
            win_sym = str(win.get("symbol", "")).strip().upper()
            start_date = str(win.get("start_date", "")).strip()
            end_date = str(win.get("end_date", "")).strip()
            if win_sym and win_sym == prop_sym and start_date and end_date and start_date <= eval_date <= end_date:
                add_veto(
                    "INSIDER_BLACKOUT_ACTIVE",
                    f"Symbol '{proposal.symbol}' is in an active insider trading blackout window ({start_date} to {end_date} ET; eval_date={eval_date}); both BUY and SELL orders are prohibited",
                )
                break

    # 3b. Order-type enforcement (LIMIT-only by default unless allow_market_orders=True)
    if proposal.order_type != OrderType.LIMIT and not eff_allow_market_orders:
        add_veto(
            "MARKET_ORDER_FORBIDDEN",
            f"Order type '{proposal.order_type.value}' is forbidden by policy; LIMIT orders are required unless allow_market_orders=True",
        )

    # 4. Shorting check
    held_qty = portfolio.held_quantity(proposal.symbol)
    is_reducing_position = proposal.side == Side.SELL and held_qty >= proposal.quantity
    if proposal.side == Side.SELL and not eff_allow_shorting and held_qty < proposal.quantity:
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
            not exempt_entry_cap
            and policy.max_entries_per_session is not None
            and portfolio.session_entries >= policy.max_entries_per_session
        ):
            add_veto(
                "MAX_ENTRIES_PER_SESSION_EXCEEDED",
                f"Session entries ({portfolio.session_entries}) already at max_entries_per_session ({policy.max_entries_per_session})",
            )

        eval_et = proposal.created_at.astimezone(_ET)
        if not exempt_last_session and policy.block_last_session_of_week and eval_et.weekday() == 4:
            add_veto(
                "LAST_SESSION_OF_WEEK_BLOCKED",
                "Policy blocks new entries on the last session of the week (Friday ET)",
            )

        if not exempt_cutoff and policy.no_entries_after_et:
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
        if order_notional_usd > eff_max_notional:
            add_veto(
                "MAX_ORDER_NOTIONAL_EXCEEDED",
                f"Order notional ${order_notional_usd:,.2f} exceeds max_order_notional_usd ${eff_max_notional:,.2f} (sleeve={sleeve_name})",
            )

        # 8a. Cash / buying-power check (unless margin explicitly permitted or reducing long exposure)
        if proposal.side == Side.BUY and not is_reducing_position and not eff_allow_margin:
            if order_notional_usd > portfolio.cash_usd + 1e-6:
                add_veto(
                    "INSUFFICIENT_CASH",
                    f"BUY order notional ${order_notional_usd:,.2f} exceeds available cash_usd ${portfolio.cash_usd:,.2f} (allow_margin=False)",
                )

        # 8b. Max gross exposure cap (for new/expanding positions)
        if eff_max_gross_pct is not None and not is_reducing_position:
            projected_gross_pct = ((portfolio.gross_exposure_usd + order_notional_usd) / portfolio.nav_usd) * 100.0
            metrics["projected_gross_exposure_pct"] = round(projected_gross_pct, 4)
            if projected_gross_pct > eff_max_gross_pct:
                add_veto(
                    "MAX_GROSS_EXPOSURE_EXCEEDED",
                    f"Projected gross exposure {projected_gross_pct:.2f}% exceeds max_gross_exposure_pct {eff_max_gross_pct:.2f}% (sleeve={sleeve_name})",
                )

        # 8c. Single-position concentration cap (allow risk-reducing closes)
        if not is_reducing_position:
            existing_symbol_notional = portfolio.held_notional_usd(proposal.symbol)
            projected_concentration_pct = (
                (existing_symbol_notional + order_notional_usd) / portfolio.nav_usd
            ) * 100.0
            metrics["projected_position_concentration_pct"] = round(projected_concentration_pct, 4)
            if projected_concentration_pct > eff_max_concentration_pct + 1e-9:
                add_veto(
                    "MAX_POSITION_CONCENTRATION_EXCEEDED",
                    f"Projected {prop_sym} concentration {projected_concentration_pct:.2f}% exceeds max_position_concentration_pct {eff_max_concentration_pct:.2f}% (sleeve={sleeve_name})",
                )

        # 8d. Cumulative daily notional cap (anti-salami-slicing; allow risk-reducing closes)
        if not is_reducing_position:
            projected_daily_notional = daily_cumulative_notional_usd + order_notional_usd
            metrics["projected_daily_cumulative_notional_usd"] = round(projected_daily_notional, 4)
            if projected_daily_notional > eff_max_daily_cumulative_notional + 1e-6:
                add_veto(
                    "MAX_DAILY_CUMULATIVE_NOTIONAL_EXCEEDED",
                    f"Projected daily cumulative notional ${projected_daily_notional:,.2f} exceeds max_daily_cumulative_notional_usd ${eff_max_daily_cumulative_notional:,.2f} (sleeve={sleeve_name})",
                )

        # 8e. Sliding 60-second order rate limit (allow risk-reducing closes)
        if not is_reducing_position and recent_order_count_1m >= policy.max_orders_per_minute:
            add_veto(
                "ORDER_RATE_EXCEEDED",
                f"Order rate ({recent_order_count_1m} orders in last 60s) reached max_orders_per_minute ({policy.max_orders_per_minute})",
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
        elif eff_require_stop and not is_pm and not is_reducing_position:
            add_veto(
                "MISSING_STOP_LOSS",
                f"Policy requires a protective stop_price on all new non-prediction-market orders (sleeve={sleeve_name})",
            )
        elif is_pm:
            # Binary prediction market contracts have bounded downside = entry_price per contract (for BUY)
            stop_distance = entry_price if proposal.side == Side.BUY else max(0.0, 1.0 - entry_price)

        if stop_distance is not None and stop_distance > 0:
            trade_risk_usd = stop_distance * proposal.quantity
            trade_risk_pct = (trade_risk_usd / portfolio.nav_usd) * 100.0
            max_risk_usd = portfolio.nav_usd * (eff_max_risk_pct / 100.0)
            max_qty_by_risk = max_risk_usd / stop_distance
            projected_heat_pct = effective_heat_pct + trade_risk_pct

            metrics["stop_distance"] = round(stop_distance, 6)
            metrics["trade_risk_usd"] = round(trade_risk_usd, 4)
            metrics["trade_risk_pct"] = round(trade_risk_pct, 4)
            metrics["max_qty_by_risk"] = round(max_qty_by_risk, 4)
            metrics["projected_heat_pct"] = round(projected_heat_pct, 4)

            # 10. Per-trade risk cap
            if trade_risk_pct > eff_max_risk_pct:
                add_veto(
                    "MAX_RISK_PER_TRADE_EXCEEDED",
                    f"Trade risk {trade_risk_pct:.2f}% (${trade_risk_usd:,.2f}) exceeds max_risk_per_trade_pct {eff_max_risk_pct:.2f}% (max qty {max_qty_by_risk:.2f})",
                )

            # 11. Total portfolio heat cap
            if projected_heat_pct > eff_max_heat_pct:
                add_veto(
                    "MAX_TOTAL_HEAT_EXCEEDED",
                    f"Projected portfolio heat {projected_heat_pct:.2f}% exceeds max_total_heat_pct {eff_max_heat_pct:.2f}%",
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
                    p = min(proposal.confidence, policy.max_kelly_confidence)
                    q = 1.0 - p
                    full_kelly = (p * payoff_ratio - q) / payoff_ratio
                    fractional_kelly = max(0.0, full_kelly * policy.fractional_kelly_multiplier)
                    raw_kelly_risk_cap_pct = fractional_kelly * 100.0
                    # Cap untrusted caller confidence so Kelly sizing can never exceed max_risk_per_trade_pct
                    kelly_risk_cap_pct = (
                        min(raw_kelly_risk_cap_pct, eff_max_risk_pct)
                        if policy.enforce_trusted_kelly
                        else raw_kelly_risk_cap_pct
                    )
                    kelly_max_qty = (portfolio.nav_usd * (kelly_risk_cap_pct / 100.0)) / stop_distance

                    metrics["effective_kelly_confidence"] = round(p, 4)
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


class RiskFirewall:
    """Stateful deterministic pre-trade risk firewall with trusted clock, provider, and rate/notional tracking."""

    def __init__(
        self,
        *,
        policy: RiskPolicy,
        kill_switch: KillSwitch,
        portfolio_provider: Optional[PortfolioProvider] = None,
        max_snapshot_age_seconds: Optional[float] = None,
        enforce_server_clock: bool = False,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.policy = policy
        self.kill_switch = kill_switch
        self.portfolio_provider = portfolio_provider
        self._max_snapshot_age_seconds = max_snapshot_age_seconds
        self.enforce_server_clock = enforce_server_clock
        self._clock = clock
        self._lock = threading.Lock()
        self._daily_notional_by_day: dict[str, float] = {}
        self._recent_order_timestamps: deque[float] = deque()

    @property
    def max_snapshot_age_seconds(self) -> float:
        if self._max_snapshot_age_seconds is not None:
            return self._max_snapshot_age_seconds
        return self.policy.max_snapshot_age_seconds

    def now(self) -> datetime:
        """Return the authoritative server UTC timestamp."""
        return self._clock().astimezone(timezone.utc)

    def _prune_rate_window_locked(self, now_ts: float) -> None:
        cutoff = now_ts - 60.0
        while self._recent_order_timestamps and self._recent_order_timestamps[0] <= cutoff:
            self._recent_order_timestamps.popleft()

    def daily_cumulative_notional_usd(self, now: Optional[datetime] = None) -> float:
        day_key = (now or self.now()).astimezone(timezone.utc).date().isoformat()
        with self._lock:
            return self._daily_notional_by_day.get(day_key, 0.0)

    def recent_order_count_1m(self, now: Optional[datetime] = None) -> int:
        now_ts = (now or self.now()).astimezone(timezone.utc).timestamp()
        with self._lock:
            self._prune_rate_window_locked(now_ts)
            return len(self._recent_order_timestamps)

    def record_approved_order(
        self,
        proposal: TradeProposal,
        *,
        is_reducing_position: bool = False,
        now: Optional[datetime] = None,
    ) -> None:
        """Record an approved order into the UTC-day notional accumulator and 60s rate window."""
        eval_now = (now or self.now()).astimezone(timezone.utc)
        now_ts = eval_now.timestamp()
        day_key = eval_now.date().isoformat()
        notional = (
            proposal.quantity * proposal.limit_price
            if (proposal.limit_price is not None and proposal.limit_price > 0)
            else 0.0
        )
        with self._lock:
            self._prune_rate_window_locked(now_ts)
            if not is_reducing_position:
                self._recent_order_timestamps.append(now_ts)
                if notional > 0:
                    self._daily_notional_by_day[day_key] = (
                        self._daily_notional_by_day.get(day_key, 0.0) + notional
                    )

    def resolve_portfolio(
        self,
        caller_portfolio: Optional[PortfolioSnapshot] = None,
        *,
        now: Optional[datetime] = None,
    ) -> tuple[Optional[PortfolioSnapshot], Optional[tuple[str, str]], dict[str, Any]]:
        """Resolve authoritative portfolio snapshot and verify freshness when a provider is configured."""
        eval_now = (now or self.now()).astimezone(timezone.utc)
        meta: dict[str, Any] = {}

        if self.portfolio_provider is not None:
            meta["portfolio_source"] = "trusted_provider"
            try:
                snapshot = self.portfolio_provider.get_snapshot()
            except Exception as exc:
                return (
                    None,
                    ("STALE_PORTFOLIO_SNAPSHOT", f"Trusted portfolio provider failed: {type(exc).__name__}: {exc}"),
                    meta,
                )
            age_seconds = (eval_now - snapshot.timestamp.astimezone(timezone.utc)).total_seconds()
            meta["portfolio_snapshot_age_seconds"] = round(age_seconds, 4)
            if age_seconds > self.max_snapshot_age_seconds or age_seconds < -5.0:
                return (
                    snapshot,
                    (
                        "STALE_PORTFOLIO_SNAPSHOT",
                        f"Portfolio snapshot age ({age_seconds:.2f}s) exceeds max_snapshot_age_seconds ({self.max_snapshot_age_seconds:.2f}s)",
                    ),
                    meta,
                )
            return snapshot, None, meta

        meta["portfolio_source"] = "caller_supplied"
        if caller_portfolio is None:
            return (
                None,
                ("MISSING_PORTFOLIO_SNAPSHOT", "Portfolio snapshot is required when no trusted PortfolioProvider is configured"),
                meta,
            )
        return caller_portfolio, None, meta

    def evaluate_proposal(
        self,
        proposal: TradeProposal,
        portfolio: Optional[PortfolioSnapshot] = None,
        *,
        now: Optional[datetime] = None,
        record_approval: bool = True,
        force_server_clock: bool = False,
    ) -> RiskDecision:
        """Evaluate a proposal enforcing trusted clock, trusted portfolio provider, concentration, daily notional, and rate caps."""
        eval_now = (now or self.now()).astimezone(timezone.utc)
        effective_proposal = (
            proposal.model_copy(update={"created_at": eval_now})
            if (self.enforce_server_clock or force_server_clock)
            else proposal
        )

        resolved_portfolio, provider_err, meta = self.resolve_portfolio(portfolio, now=eval_now)
        if provider_err is not None:
            code, reason = provider_err
            return RiskDecision(
                proposal_id=effective_proposal.proposal_id,
                status=DecisionStatus.VETOED,
                approved=False,
                reason_codes=[code],
                reasons=[reason],
                metrics={"policy_version": self.policy.policy_version, **meta},
                evaluated_at=eval_now,
            )

        assert resolved_portfolio is not None
        day_key = eval_now.date().isoformat()
        now_ts = eval_now.timestamp()

        with self._lock:
            self._prune_rate_window_locked(now_ts)
            cum_notional = self._daily_notional_by_day.get(day_key, 0.0)
            recent_count = len(self._recent_order_timestamps)

        decision = evaluate_proposal(
            proposal=effective_proposal,
            portfolio=resolved_portfolio,
            policy=self.policy,
            kill_switch=self.kill_switch,
            daily_cumulative_notional_usd=cum_notional,
            recent_order_count_1m=recent_count,
        )
        decision.metrics.update(meta)
        decision.evaluated_at = eval_now

        if decision.approved and record_approval:
            held_qty = resolved_portfolio.held_quantity(effective_proposal.symbol)
            is_reducing = effective_proposal.side == Side.SELL and held_qty >= effective_proposal.quantity
            self.record_approved_order(
                effective_proposal,
                is_reducing_position=is_reducing,
                now=eval_now,
            )

        return decision
