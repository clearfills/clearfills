"""Unit tests for pre-trade tax & compliance firewall vetoes (PFIC, wash-sale/superficial-loss, insider blackout)."""

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
    default_allocation_sleeves,
)

_ET = ZoneInfo("America/New_York")


def _make_service(tmp_path: Path, name: str, **policy_kwargs) -> FirewallService:
    policy = RiskPolicy(
        max_risk_per_trade_pct=1.0,
        max_total_heat_pct=10.0,
        max_daily_loss_pct=2.0,
        enforce_kelly_sizing=False,
        sleeves=default_allocation_sleeves(),
        **policy_kwargs,
    )
    return FirewallService.from_data_dir(
        tmp_path / name,
        policy=policy,
        initialize_armed=True,
        enforce_server_clock=False,
    )


def test_pfic_hard_veto_for_us_tax_person_and_backward_compatibility(tmp_path: Path) -> None:
    portfolio = PortfolioSnapshot(nav_usd=100_000.0, cash_usd=100_000.0)

    # 1. Default policy (is_us_tax_person=False) permits Canadian ETFs (VEQT, .TO)
    svc_default = _make_service(tmp_path, "non_us_default")
    veqt_buy = TradeProposal(
        agent_id="alloc-agent",
        venue="ibkr",
        symbol="VEQT",
        side=Side.BUY,
        quantity=100.0,
        limit_price=44.0,
    )
    assert svc_default.propose(veqt_buy, portfolio).approved is True

    # 2. US tax person (is_us_tax_person=True) hard-vetoes listed PFIC symbols & .TO tickers on BUY
    svc_us = _make_service(tmp_path, "us_person", is_us_tax_person=True)

    d_veqt = svc_us.propose(veqt_buy, portfolio)
    assert d_veqt.approved is False
    assert "PFIC_FORBIDDEN_FOR_US_PERSON" in d_veqt.reason_codes
    assert any("8621" in r for r in d_veqt.reasons)

    tsx_buy = TradeProposal(
        agent_id="alloc-agent",
        venue="ibkr",
        symbol="XIU.TO",
        side=Side.BUY,
        quantity=100.0,
        limit_price=36.0,
        stop_price=34.0,
    )
    d_tsx = svc_us.propose(tsx_buy, portfolio)
    assert d_tsx.approved is False
    assert "PFIC_FORBIDDEN_FOR_US_PERSON" in d_tsx.reason_codes

    # 3. US-domiciled ETFs (VT, SGOV) are approved for US tax persons
    vt_buy = TradeProposal(
        agent_id="alloc-agent",
        venue="ibkr",
        symbol="VT",
        side=Side.BUY,
        quantity=50.0,
        limit_price=120.0,
    )
    assert svc_us.propose(vt_buy, portfolio).approved is True

    # 4. Liquidating an existing PFIC position (Side.SELL) is NOT blocked
    pf_with_veqt = PortfolioSnapshot(
        nav_usd=100_000.0,
        cash_usd=90_000.0,
        open_positions=[
            Position(
                symbol="VEQT",
                venue="ibkr",
                quantity=100.0,
                avg_entry_price=42.0,
                current_price=44.0,
            )
        ],
    )
    veqt_sell = TradeProposal(
        agent_id="alloc-agent",
        venue="ibkr",
        symbol="VEQT",
        side=Side.SELL,
        quantity=100.0,
        limit_price=44.0,
    )
    d_sell = svc_us.propose(veqt_sell, pf_with_veqt)
    assert d_sell.approved is True
    assert "PFIC_FORBIDDEN_FOR_US_PERSON" not in d_sell.reason_codes


def test_superficial_loss_and_wash_sale_hard_veto(tmp_path: Path) -> None:
    svc = _make_service(
        tmp_path,
        "wash_sale",
        recent_loss_sale_symbols=["voo", "SGOV "],
    )
    portfolio = PortfolioSnapshot(
        nav_usd=100_000.0,
        cash_usd=80_000.0,
        open_positions=[
            Position(
                symbol="VOO",
                venue="ibkr",
                quantity=20.0,
                avg_entry_price=510.0,
                current_price=480.0,
            )
        ],
    )

    # 1. Re-buying VOO within 30-day loss window -> SUPERFICIAL_LOSS_BLOCKED
    voo_buy = TradeProposal(
        agent_id="rebalancer",
        venue="ibkr",
        symbol="VOO",
        side=Side.BUY,
        quantity=10.0,
        limit_price=480.0,
    )
    d_voo = svc.propose(voo_buy, portfolio)
    assert d_voo.approved is False
    assert "SUPERFICIAL_LOSS_BLOCKED" in d_voo.reason_codes

    # 2. Buying non-identical tax-safe substitute VTI -> APPROVED
    vti_buy = TradeProposal(
        agent_id="rebalancer",
        venue="ibkr",
        symbol="VTI",
        side=Side.BUY,
        quantity=10.0,
        limit_price=280.0,
    )
    assert svc.propose(vti_buy, portfolio).approved is True

    # 3. Selling remaining VOO shares -> APPROVED (SELL is never wash-sale blocked)
    voo_sell = TradeProposal(
        agent_id="rebalancer",
        venue="ibkr",
        symbol="VOO",
        side=Side.SELL,
        quantity=20.0,
        limit_price=480.0,
    )
    d_sell = svc.propose(voo_sell, portfolio)
    assert d_sell.approved is True
    assert "SUPERFICIAL_LOSS_BLOCKED" not in d_sell.reason_codes


def test_insider_blackout_window_blocks_both_buy_and_sell_in_et_timezone(tmp_path: Path) -> None:
    svc = _make_service(
        tmp_path,
        "blackout",
        insider_blackout_windows=[
            {"symbol": "NVDA", "start_date": "2026-11-01", "end_date": "2026-12-01"}
        ],
    )
    portfolio = PortfolioSnapshot(
        nav_usd=200_000.0,
        cash_usd=150_000.0,
        open_positions=[
            Position(
                symbol="NVDA",
                venue="ibkr",
                quantity=100.0,
                avg_entry_price=125.0,
                current_price=140.0,
                stop_price=120.0,
            )
        ],
    )

    # 1. Inside window (2026-11-15 ET) -> BUY vetoed with INSIDER_BLACKOUT_ACTIVE
    inside_ts = datetime(2026, 11, 15, 11, 0, tzinfo=_ET).astimezone(timezone.utc)
    nvda_buy = TradeProposal(
        agent_id="exec-agent",
        venue="ibkr",
        symbol="NVDA",
        side=Side.BUY,
        quantity=10.0,
        limit_price=140.0,
        stop_price=130.0,
        created_at=inside_ts,
    )
    d_buy = svc.propose(nvda_buy, portfolio)
    assert d_buy.approved is False
    assert "INSIDER_BLACKOUT_ACTIVE" in d_buy.reason_codes

    # 2. Inside window (even boundary end_date 2026-12-01 23:30 ET = 2026-12-02 04:30 UTC!) -> SELL ALSO vetoed!
    end_boundary_et = datetime(2026, 12, 1, 23, 30, tzinfo=_ET).astimezone(timezone.utc)
    nvda_sell = TradeProposal(
        agent_id="exec-agent",
        venue="ibkr",
        symbol="NVDA",
        side=Side.SELL,
        quantity=50.0,
        limit_price=140.0,
        created_at=end_boundary_et,
    )
    d_sell_inside = svc.propose(nvda_sell, portfolio)
    assert d_sell_inside.approved is False
    assert "INSIDER_BLACKOUT_ACTIVE" in d_sell_inside.reason_codes

    # 3. After blackout window closes (2026-12-02 10:30 ET) -> both BUY and SELL approved
    after_ts = datetime(2026, 12, 2, 10, 30, tzinfo=_ET).astimezone(timezone.utc)
    assert svc.propose(nvda_buy.model_copy(update={"created_at": after_ts}), portfolio).approved is True
    assert svc.propose(nvda_sell.model_copy(update={"created_at": after_ts}), portfolio).approved is True

    # 4. Unrelated symbol (MSFT) during NVDA blackout -> approved
    msft_buy = TradeProposal(
        agent_id="exec-agent",
        venue="ibkr",
        symbol="MSFT",
        side=Side.BUY,
        quantity=10.0,
        limit_price=420.0,
        stop_price=400.0,
        created_at=inside_ts,
    )
    assert svc.propose(msft_buy, portfolio).approved is True


def test_policy_yaml_roundtrip_preserves_compliance_fields(tmp_path: Path) -> None:
    yaml_path = tmp_path / "policy.yaml"
    p = RiskPolicy(
        is_us_tax_person=True,
        recent_loss_sale_symbols=["VOO"],
        insider_blackout_windows=[{"symbol": "AAPL", "start_date": "2026-10-15", "end_date": "2026-11-05"}],
    )
    p.to_yaml(yaml_path)
    loaded = RiskPolicy.from_yaml(yaml_path)
    assert loaded.is_us_tax_person is True
    assert loaded.recent_loss_sale_symbols == ["VOO"]
    assert loaded.insider_blackout_windows == [
        {"symbol": "AAPL", "start_date": "2026-10-15", "end_date": "2026-11-05"}
    ]
    assert "VEQT" in loaded.pfic_symbols
