"""Tests for ClearFills Desk OS."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from clearfills_desk import DESK_ROLES, DeskConfig, DeskRuntime, sanitize_text
from clearfills_firewall import PortfolioSnapshot, Side, TradeProposal

_ET = ZoneInfo("America/New_York")


def test_desk_os_config_and_authoritative_firewall(tmp_path: Path) -> None:
    example_yaml = Path(__file__).resolve().parents[1] / "config" / "desk_rules.example.yaml"
    cfg = DeskConfig.from_yaml(example_yaml)
    assert cfg.risk.max_total_heat_pct == 12.0
    assert cfg.risk.max_entries_per_session == 4
    assert cfg.risk.block_last_session_of_week is True
    assert len(DESK_ROLES) == 6

    rt = DeskRuntime(config=cfg, state_dir=tmp_path)
    mon_morning = datetime(2026, 11, 23, 10, 30, tzinfo=_ET).astimezone(timezone.utc)
    proposal = TradeProposal(
        agent_id="strategist",
        venue="ibkr",
        symbol="NVDA",
        side=Side.BUY,
        quantity=25.0,
        limit_price=135.0,
        stop_price=129.0,
        created_at=mon_morning,
    )
    pf = PortfolioSnapshot(nav_usd=100_000.0, cash_usd=100_000.0, session_entries=2)
    decision = rt.evaluate_proposal(proposal, pf)
    assert decision.approved is True
    assert decision.attestation is not None

    # Single-use dispatch succeeds once, then rejects replay
    assert rt.verify_dispatch(decision.attestation, proposal) is True
    assert rt.verify_dispatch(decision.attestation, proposal) is False


def test_telemetry_sanitizer_strips_secrets() -> None:
    raw = "Account DU1234567 on box.tail1234.ts.net at 100.64.1.2 with cf_sk_abcdef1234567890"
    cleaned = sanitize_text(raw)
    assert "DU1234567" not in cleaned
    assert "tail1234.ts.net" not in cleaned
    assert "100.64.1.2" not in cleaned
    assert "cf_sk_" not in cleaned
