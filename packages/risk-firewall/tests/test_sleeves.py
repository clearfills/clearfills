"""Unit tests for per-sleeve / asset-class risk policy profiles in clearfills-firewall."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from clearfills_firewall import (
    FirewallService,
    OrderType,
    PortfolioSnapshot,
    RiskPolicy,
    Side,
    SleevePolicy,
    TradeProposal,
    default_allocation_sleeves,
)

# Friday 2026-11-27 14:00 ET (19:00 UTC)
_FRIDAY_ET = datetime(2026, 11, 27, 19, 0, tzinfo=timezone.utc)


def _multi_sleeve_policy() -> RiskPolicy:
    return RiskPolicy(
        max_risk_per_trade_pct=1.0,
        max_total_heat_pct=12.0,
        max_daily_loss_pct=2.0,
        max_order_notional_usd=50_000.0,
        require_stop_loss=True,
        max_entries_per_session=4,
        block_last_session_of_week=True,
        no_entries_after_et="15:50",
        sleeves=default_allocation_sleeves(),
    )


def _portfolio(*, nav: float = 500_000.0, session_entries: int = 4, daily_pnl: float = 0.0) -> PortfolioSnapshot:
    return PortfolioSnapshot(
        account_id="***001",
        nav_usd=nav,
        cash_usd=nav,
        daily_pnl_usd=daily_pnl,
        session_entries=session_entries,
        open_positions=[],
    )


def test_cash_equivalent_sleeve_allows_no_stop_high_notional_and_friday(tmp_path: Path) -> None:
    svc = FirewallService.from_data_dir(tmp_path / "fw", policy=_multi_sleeve_policy(), initialize_armed=True)
    proposal = TradeProposal(
        agent_id="allocator-agent",
        venue="ibkr",
        symbol="SGOV",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=2000,
        limit_price=100.25,  # $200,500 > $50k active cap, <= $500k sleeve cap
        stop_price=None,
        created_at=_FRIDAY_ET,
    )
    decision = svc.propose(proposal=proposal, portfolio=_portfolio(session_entries=4))
    assert decision.approved is True
    assert decision.attestation is not None
    assert decision.metrics["sleeve"] == "cash_equivalent"


def test_core_index_sleeve_allows_no_stop_but_enforces_sleeve_notional_cap(tmp_path: Path) -> None:
    svc = FirewallService.from_data_dir(tmp_path / "fw", policy=_multi_sleeve_policy(), initialize_armed=True)
    ok_prop = TradeProposal(
        agent_id="allocator-agent",
        venue="ibkr",
        symbol="VT",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=1500,
        limit_price=120.0,  # $180k <= $500k
        stop_price=None,
        created_at=_FRIDAY_ET,
    )
    ok_dec = svc.propose(proposal=ok_prop, portfolio=_portfolio(session_entries=4))
    assert ok_dec.approved is True
    assert ok_dec.metrics["sleeve"] == "core_index"

    too_big = TradeProposal(
        agent_id="allocator-agent",
        venue="ibkr",
        symbol="VT",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=5000,
        limit_price=120.0,  # $600k > $500k sleeve cap
        stop_price=None,
        created_at=_FRIDAY_ET,
    )
    veto_dec = svc.propose(proposal=too_big, portfolio=_portfolio(session_entries=4))
    assert veto_dec.approved is False
    assert "MAX_ORDER_NOTIONAL_EXCEEDED" in veto_dec.reason_codes


def test_active_trading_still_enforces_strict_stop_notional_friday_and_entry_cap(tmp_path: Path) -> None:
    svc = FirewallService.from_data_dir(tmp_path / "fw", policy=_multi_sleeve_policy(), initialize_armed=True)
    rogue = TradeProposal(
        agent_id="swing-bot",
        venue="ibkr",
        symbol="GOOG",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=500,
        limit_price=180.0,  # $90k > $50k cap
        stop_price=None,  # Missing stop-loss
        created_at=_FRIDAY_ET,
    )
    dec = svc.propose(proposal=rogue, portfolio=_portfolio(session_entries=4))
    assert dec.approved is False
    assert dec.metrics["sleeve"] == "active_trading"
    assert "MISSING_STOP_LOSS" in dec.reason_codes
    assert "MAX_ORDER_NOTIONAL_EXCEEDED" in dec.reason_codes
    assert "LAST_SESSION_OF_WEEK_BLOCKED" in dec.reason_codes
    assert "MAX_ENTRIES_PER_SESSION_EXCEEDED" in dec.reason_codes


def test_kill_switch_and_daily_loss_still_block_all_sleeves(tmp_path: Path) -> None:
    svc = FirewallService.from_data_dir(tmp_path / "fw", policy=_multi_sleeve_policy(), initialize_armed=True)
    proposal = TradeProposal(
        agent_id="allocator-agent",
        venue="ibkr",
        symbol="SGOV",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=100,
        limit_price=100.0,
        created_at=_FRIDAY_ET,
    )
    # Daily loss >= 2% blocks even cash_equivalent sleeve
    loss_dec = svc.propose(proposal=proposal, portfolio=_portfolio(nav=100_000.0, daily_pnl=-2500.0))
    assert loss_dec.approved is False
    assert "DAILY_LOSS_LIMIT_BREACHED" in loss_dec.reason_codes

    # Kill-switch blocks even cash_equivalent sleeve
    svc.kill_switch.trip(reason="manual drill", actor="operator")
    ks_dec = svc.propose(proposal=proposal, portfolio=_portfolio())
    assert ks_dec.approved is False
    assert "KILL_SWITCH_TRIPPED" in ks_dec.reason_codes


def test_sleeve_policy_yaml_roundtrip(tmp_path: Path) -> None:
    policy = _multi_sleeve_policy()
    policy.sleeves["custom"] = SleevePolicy(symbols=["GOOG"], require_stop_loss=False, max_order_notional_usd=100_000.0)
    out = tmp_path / "policy.yaml"
    policy.to_yaml(out)
    loaded = RiskPolicy.from_yaml(out)
    assert loaded.resolve_sleeve("SGOV")[0] == "cash_equivalent"
    assert loaded.resolve_sleeve("goog")[0] == "custom"
    assert loaded.resolve_sleeve("NVDA")[0] == "active_trading"
