"""Unit tests for v0.5.2 risk-firewall hardening rules and O(1) audit ledger tail state."""

from __future__ import annotations

from pathlib import Path

import pytest

from clearfills_firewall import (
    AuditLedger,
    FirewallService,
    GENESIS_HASH,
    OrderType,
    PortfolioSnapshot,
    Position,
    RiskPolicy,
    Side,
    SleevePolicy,
    TradeProposal,
    default_allocation_sleeves,
)


def test_market_order_vetoed_even_with_limit_and_stop_unless_allowed(tmp_path: Path) -> None:
    svc_default = FirewallService.from_data_dir(
        tmp_path / "fw_default",
        policy=RiskPolicy(),
        initialize_armed=True,
    )
    portfolio = PortfolioSnapshot(
        account_id="DU0000001",
        nav_usd=100_000.0,
        cash_usd=100_000.0,
    )
    market_prop = TradeProposal(
        agent_id="swing-agent",
        venue="ibkr",
        symbol="NVDA",
        side=Side.BUY,
        order_type=OrderType.MARKET,
        quantity=50.0,
        limit_price=130.0,
        stop_price=120.0,
    )

    vetoed = svc_default.propose(market_prop, portfolio)
    assert vetoed.approved is False
    assert "MARKET_ORDER_FORBIDDEN" in vetoed.reason_codes

    # Global allow_market_orders=True permits compliant MARKET order
    svc_allow = FirewallService.from_data_dir(
        tmp_path / "fw_allow",
        policy=RiskPolicy(allow_market_orders=True),
        initialize_armed=True,
    )
    approved = svc_allow.propose(market_prop, portfolio)
    assert approved.approved is True
    assert "MARKET_ORDER_FORBIDDEN" not in approved.reason_codes

    # Sleeve-level allow_market_orders=True permits only symbols in that sleeve
    sleeve_policy = RiskPolicy(
        sleeves={
            "liquid_etf": SleevePolicy(
                symbols=["SPY"],
                require_stop_loss=False,
                allow_market_orders=True,
            )
        }
    )
    svc_sleeve = FirewallService.from_data_dir(
        tmp_path / "fw_sleeve",
        policy=sleeve_policy,
        initialize_armed=True,
    )
    spy_mkt = TradeProposal(
        agent_id="hedger",
        venue="ibkr",
        symbol="SPY",
        side=Side.BUY,
        order_type=OrderType.MARKET,
        quantity=10.0,
        limit_price=500.0,
    )
    assert svc_sleeve.propose(spy_mkt, portfolio).approved is True
    assert "MARKET_ORDER_FORBIDDEN" in svc_sleeve.propose(market_prop, portfolio).reason_codes


def test_stop_exempt_cash_equivalent_sleeve_does_not_inflate_portfolio_heat(tmp_path: Path) -> None:
    policy = RiskPolicy(
        max_risk_per_trade_pct=1.0,
        max_total_heat_pct=8.0,
        sleeves=default_allocation_sleeves(),
    )
    svc = FirewallService.from_data_dir(
        tmp_path / "fw_heat",
        policy=policy,
        initialize_armed=True,
    )
    # $90k in SGOV (cash_equivalent, require_stop_loss=False) + $10k cash = $100k NAV
    portfolio = PortfolioSnapshot(
        account_id="U0000001",
        nav_usd=100_000.0,
        cash_usd=10_000.0,
        open_positions=[
            Position(
                symbol="SGOV",
                venue="ibkr",
                quantity=900.0,
                avg_entry_price=100.0,
                current_price=100.0,
                stop_price=None,
            )
        ],
    )
    assert portfolio.current_heat_pct == pytest.approx(9.0)

    # Compliant NVDA trade: 50 * $150 = $7,500 (<= $10k cash), risk = 50 * $10 = $500 (0.5% NAV)
    nvda_prop = TradeProposal(
        agent_id="swing-agent",
        venue="ibkr",
        symbol="NVDA",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=50.0,
        limit_price=150.0,
        stop_price=140.0,
    )
    decision = svc.propose(nvda_prop, portfolio)
    assert decision.approved is True
    assert decision.reason_codes == []
    assert decision.metrics["raw_portfolio_heat_pct"] == pytest.approx(9.0)
    assert decision.metrics["current_heat_pct"] == pytest.approx(0.0)
    assert decision.metrics["projected_heat_pct"] == pytest.approx(0.5)


def test_insufficient_cash_vetoes_buy_when_margin_disabled_and_allows_when_enabled(tmp_path: Path) -> None:
    portfolio = PortfolioSnapshot(
        account_id="U0000001",
        nav_usd=100_000.0,
        cash_usd=10_000.0,
    )
    # $15,000 notional > $10,000 cash_usd, risk = 100 * $5 = $500 (0.5% NAV)
    buy_prop = TradeProposal(
        agent_id="swing-agent",
        venue="ibkr",
        symbol="AAPL",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=100.0,
        limit_price=150.0,
        stop_price=145.0,
    )

    svc_cash_only = FirewallService.from_data_dir(
        tmp_path / "fw_no_margin",
        policy=RiskPolicy(allow_margin=False),
        initialize_armed=True,
    )
    vetoed = svc_cash_only.propose(buy_prop, portfolio)
    assert vetoed.approved is False
    assert "INSUFFICIENT_CASH" in vetoed.reason_codes

    svc_margin = FirewallService.from_data_dir(
        tmp_path / "fw_margin",
        policy=RiskPolicy(allow_margin=True),
        initialize_armed=True,
    )
    approved = svc_margin.propose(buy_prop, portfolio)
    assert approved.approved is True
    assert "INSUFFICIENT_CASH" not in approved.reason_codes


def test_max_kelly_confidence_clamps_hallucinated_certainty(tmp_path: Path) -> None:
    # Default max_kelly_confidence=0.75, fractional_kelly_multiplier=0.25
    # With 1:1 payoff (entry=100, stop=99, target=101):
    # Clamped p=0.75 -> full_kelly = (0.75*1 - 0.25)/1 = 0.50 -> quarter_kelly = 0.125 (12.5% risk cap)
    # Unclamped p=0.99 would give full_kelly = 0.98 -> quarter_kelly = 0.245 (24.5% risk cap)
    policy = RiskPolicy(
        max_risk_per_trade_pct=20.0,
        max_total_heat_pct=25.0,
        max_order_notional_usd=500_000.0,
        fractional_kelly_multiplier=0.25,
        max_kelly_confidence=0.75,
        enforce_kelly_sizing=True,
    )
    svc = FirewallService.from_data_dir(
        tmp_path / "fw_kelly",
        policy=policy,
        initialize_armed=True,
    )
    portfolio = PortfolioSnapshot(
        account_id="DU0000001",
        nav_usd=100_000.0,
        cash_usd=100_000.0,
    )

    # 15% trade risk (150 shares * $100 stop distance = $15,000 on $100k NAV; entry=$200, stop=$100, target=$300 -> 1:1 R:R)
    # Wait: notional = 150 * 200 = $30,000 <= $100,000 cash.
    # Trade risk = 15% > clamped quarter-Kelly 12.5% (would have been < 24.5% if unclamped at 0.99!)
    over_kelly = TradeProposal(
        agent_id="overconfident-llm",
        venue="ibkr",
        symbol="NVDA",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=150.0,
        limit_price=200.0,
        stop_price=100.0,
        target_price=300.0,
        confidence=0.99,
    )
    dec = svc.propose(over_kelly, portfolio)
    assert dec.approved is False
    assert dec.metrics["effective_kelly_confidence"] == pytest.approx(0.75)
    assert dec.metrics["fractional_kelly_pct"] == pytest.approx(12.5)
    assert "KELLY_POSITION_SIZE_EXCEEDED" in dec.reason_codes


def test_audit_ledger_o1_tail_state_across_multi_chunk_chains(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(ledger_path)

    assert ledger._get_tail_state() == (0, GENESIS_HASH)

    # Append enough entries with ~300-byte payloads to exceed multiple 8192-byte chunks
    entries = []
    for i in range(1, 65):
        entry = ledger.append(
            event_type="PROPOSAL_EVALUATED",
            actor=f"agent-{i % 4}",
            payload={"seq_hint": i, "blob": "x" * 256},
        )
        entries.append(entry)

    assert ledger_path.stat().st_size > 16_384  # > 2 chunks of 8192 bytes

    # Re-open a fresh AuditLedger instance to verify cold-start O(1) tail seek
    reopened = AuditLedger(ledger_path)
    tail_seq, tail_hash = reopened._get_tail_state()
    assert tail_seq == 64
    assert tail_hash == entries[-1].entry_hash

    e65 = reopened.append("DISPATCH_ALLOWED", "trader", {"order_id": 9001})
    assert e65.seq == 65
    assert e65.prev_hash == entries[-1].entry_hash

    valid, err, count = reopened.verify_chain()
    assert valid is True
    assert err is None
    assert count == 65
