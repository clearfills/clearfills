"""Tests for v0.2.0 institutional desk policy rules in clearfills-firewall."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from clearfills_firewall import (
    FirewallService,
    PortfolioSnapshot,
    Position,
    RiskPolicy,
    Side,
    TradeProposal,
)

_ET = ZoneInfo("America/New_York")


def _make_service(tmp_path: Path, **policy_kwargs) -> FirewallService:
    policy = RiskPolicy(
        max_risk_per_trade_pct=1.0,
        max_total_heat_pct=12.0,
        max_daily_loss_pct=2.0,
        enforce_kelly_sizing=False,
        **policy_kwargs,
    )
    return FirewallService.from_data_dir(
        tmp_path,
        policy=policy,
        initialize_armed=True,
        enforce_server_clock=False,
    )


def test_session_entries_cutoff_and_friday_block(tmp_path: Path) -> None:
    svc = _make_service(
        tmp_path,
        max_entries_per_session=4,
        block_last_session_of_week=True,
        no_entries_after_et="15:30",
        max_gross_exposure_pct=100.0,
    )

    # Monday 10:30 ET, 3 prior entries -> APPROVED
    mon_morning = datetime(2026, 11, 23, 10, 30, tzinfo=_ET).astimezone(timezone.utc)
    ok_prop = TradeProposal(
        agent_id="desk-v2",
        venue="ibkr",
        symbol="AAPL",
        side=Side.BUY,
        quantity=25.0,
        limit_price=200.0,
        stop_price=190.0,
        created_at=mon_morning,
    )
    pf_ok = PortfolioSnapshot(nav_usd=100_000.0, cash_usd=100_000.0, session_entries=3)
    d_ok = svc.propose(ok_prop, pf_ok)
    assert d_ok.approved is True

    # 4th entry already used -> MAX_ENTRIES_PER_SESSION_EXCEEDED
    pf_full = PortfolioSnapshot(nav_usd=100_000.0, cash_usd=100_000.0, session_entries=4)
    d_entries = svc.propose(ok_prop, pf_full)
    assert d_entries.approved is False
    assert "MAX_ENTRIES_PER_SESSION_EXCEEDED" in d_entries.reason_codes

    # Monday 15:35 ET -> SESSION_CUTOFF_EXCEEDED
    mon_late = datetime(2026, 11, 23, 15, 35, tzinfo=_ET).astimezone(timezone.utc)
    late_prop = ok_prop.model_copy(update={"created_at": mon_late})
    d_late = svc.propose(late_prop, pf_ok)
    assert d_late.approved is False
    assert "SESSION_CUTOFF_EXCEEDED" in d_late.reason_codes

    # Friday 11:00 ET -> LAST_SESSION_OF_WEEK_BLOCKED
    fri_morning = datetime(2026, 11, 27, 11, 0, tzinfo=_ET).astimezone(timezone.utc)
    fri_prop = ok_prop.model_copy(update={"created_at": fri_morning})
    d_fri = svc.propose(fri_prop, pf_ok)
    assert d_fri.approved is False
    assert "LAST_SESSION_OF_WEEK_BLOCKED" in d_fri.reason_codes

    # Closing SELL on Friday at 15:45 ET is STILL ALLOWED (never block risk reduction!)
    fri_late = datetime(2026, 11, 27, 15, 45, tzinfo=_ET).astimezone(timezone.utc)
    sell_prop = TradeProposal(
        agent_id="desk-v2",
        venue="ibkr",
        symbol="AAPL",
        side=Side.SELL,
        quantity=25.0,
        limit_price=205.0,
        created_at=fri_late,
    )
    pf_holding = PortfolioSnapshot(
        nav_usd=100_000.0,
        cash_usd=95_000.0,
        session_entries=4,
        open_positions=[
            Position(
                symbol="AAPL",
                venue="ibkr",
                quantity=25.0,
                avg_entry_price=200.0,
                current_price=205.0,
                stop_price=190.0,
            )
        ],
    )
    d_exit = svc.propose(sell_prop, pf_holding)
    assert d_exit.approved is True
