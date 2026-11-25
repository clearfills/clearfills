"""Unit tests for extensible Python custom guards (@firewall.guard) and DeclarativeGuardRule."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from clearfills_firewall import (
    DeclarativeGuardRule,
    FirewallService,
    GuardViolation,
    OrderType,
    PortfolioSnapshot,
    Side,
    TradeProposal,
)


def _sample_portfolio() -> PortfolioSnapshot:
    return PortfolioSnapshot(
        nav_usd=500_000.0,
        cash_usd=250_000.0,
        daily_pnl_usd=0.0,
        open_positions=[],
    )


def _valid_proposal(symbol: str = "NVDA", qty: float = 50.0, limit_price: float = 135.0) -> TradeProposal:
    return TradeProposal(
        agent_id="test-agent",
        venue="ibkr",
        symbol=symbol,
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=qty,
        limit_price=limit_price,
        stop_price=round(limit_price * 0.95, 2),
        reasoning_trace="Valid test proposal",
    )


def test_python_custom_guard_blocks_and_allows(tmp_path: Path) -> None:
    fw = FirewallService.from_data_dir(tmp_path, initialize_armed=True)

    @fw.guard("earnings_blackout")
    def block_earnings(proposal: TradeProposal, portfolio: PortfolioSnapshot):
        if proposal.symbol == "NVDA":
            return GuardViolation(
                code="CUSTOM_EARNINGS_BLACKOUT",
                reason="NVDA is inside the 48h earnings blackout window.",
                guard_name="earnings_blackout",
            )
        return None

    assert fw.list_custom_guards()["python_guards"] == ["earnings_blackout"]

    blocked = fw.propose(_valid_proposal("NVDA"), _sample_portfolio())
    assert blocked.approved is False
    assert blocked.attestation is None
    assert "CUSTOM_EARNINGS_BLACKOUT" in blocked.reason_codes

    allowed = fw.propose(_valid_proposal("AAPL", qty=20, limit_price=200.0), _sample_portfolio())
    assert allowed.approved is True
    assert allowed.attestation is not None

    assert fw.unregister_guard("earnings_blackout") is True
    after_unreg = fw.propose(_valid_proposal("NVDA"), _sample_portfolio())
    assert after_unreg.approved is True


def test_python_custom_guard_fails_closed_on_exception(tmp_path: Path) -> None:
    fw = FirewallService.from_data_dir(tmp_path, initialize_armed=True)

    @fw.guard("buggy_guard")
    def exploding_guard(proposal: TradeProposal, portfolio: PortfolioSnapshot):
        raise RuntimeError("external calendar API down")

    decision = fw.propose(_valid_proposal("AAPL", qty=10, limit_price=200.0), _sample_portfolio())
    assert decision.approved is False
    assert decision.attestation is None
    assert "CUSTOM_GUARD_ERROR" in decision.reason_codes


def test_declarative_guard_rules_zero_eval(tmp_path: Path) -> None:
    fw = FirewallService.from_data_dir(tmp_path, initialize_armed=True)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    fw.add_declarative_rule(
        DeclarativeGuardRule(
            rule_id="semi-cap",
            name="Semiconductor Cap",
            symbols=["NVDA", "AMD", "AVGO"],
            max_notional_usd=5_000.0,
            code="CUSTOM_SEMI_CAP",
            reason="Semiconductor buys capped at $5k.",
        )
    )
    fw.add_declarative_rule(
        DeclarativeGuardRule(
            rule_id="fomc-blackout",
            name="FOMC Blackout",
            blackout_dates=[today],
            symbols=["SPY"],
            code="CUSTOM_FOMC_BLACKOUT",
            reason="No SPY trades on FOMC day.",
        )
    )

    # $6,750 > $5,000 cap -> blocked
    d1 = fw.propose(_valid_proposal("NVDA", qty=50, limit_price=135.0), _sample_portfolio())
    assert d1.approved is False
    assert "CUSTOM_SEMI_CAP" in d1.reason_codes

    # $2,700 <= $5,000 cap -> allowed
    d2 = fw.propose(_valid_proposal("NVDA", qty=20, limit_price=135.0), _sample_portfolio())
    assert d2.approved is True

    # SPY on blackout date -> blocked
    d3 = fw.propose(_valid_proposal("SPY", qty=5, limit_price=500.0), _sample_portfolio())
    assert d3.approved is False
    assert "CUSTOM_FOMC_BLACKOUT" in d3.reason_codes
