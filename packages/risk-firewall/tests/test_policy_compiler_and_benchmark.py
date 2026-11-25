"""Tests for the Deterministic Natural-Language Policy Compiler, 25-Scenario Benchmark, and CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clearfills_firewall import (
    FirewallService,
    OrderType,
    PortfolioSnapshot,
    RiskPolicy,
    Side,
    TradeProposal,
    compile_natural_language_policy,
    run_safety_benchmark,
)


def test_compile_comprehensive_founder_prompt(tmp_path: Path) -> None:
    prompt = (
        "Cap orders at $25k, stop trading if down 2% today, max heat 6%, "
        "limit orders only, require stop loss, no shorting, "
        "block TQQQ, SQQQ, UVXY, require Touch ID above $2,500."
    )
    res = compile_natural_language_policy(prompt)

    assert res.policy.max_order_notional_usd == 25_000.0
    assert res.policy.max_daily_loss_pct == 2.0
    assert res.policy.max_total_heat_pct == 6.0
    assert res.policy.allow_market_orders is False
    assert res.policy.require_stop_loss is True
    assert res.policy.allow_shorting is False
    assert set(res.policy.blocked_symbols) == {"TQQQ", "SQQQ", "UVXY"}
    assert res.human_confirm_above_usd == 2_500.0
    assert res.self_test_passed is True
    assert "100% enforcement verified" in res.self_test_summary

    # Verify YAML round-trip into RiskPolicy.from_yaml
    yaml_path = tmp_path / "compiled.yaml"
    yaml_path.write_text(res.yaml_text, encoding="utf-8")
    loaded = RiskPolicy.from_yaml(yaml_path)
    assert loaded.max_order_notional_usd == 25_000.0
    assert loaded.blocked_symbols == ["TQQQ", "SQQQ", "UVXY"]

    # Verify compiled policy vetoes actual violations through FirewallService
    svc = FirewallService.from_data_dir(tmp_path / "fw", policy=res.policy, initialize_armed=True)
    portfolio = PortfolioSnapshot(account_id="TEST-1", nav_usd=500_000.0, cash_usd=500_000.0)

    dec_blocked = svc.propose(
        TradeProposal(
            agent_id="agent-1",
            venue="ibkr",
            symbol="SQQQ",
            side=Side.BUY,
            order_type=OrderType.LIMIT,
            quantity=100,
            limit_price=20.0,
            stop_price=18.0,
        ),
        portfolio,
    )
    assert not dec_blocked.approved
    assert "SYMBOL_BLOCKED" in dec_blocked.reason_codes

    dec_cap = svc.propose(
        TradeProposal(
            agent_id="agent-1",
            venue="ibkr",
            symbol="AAPL",
            side=Side.BUY,
            order_type=OrderType.LIMIT,
            quantity=150,
            limit_price=200.0,  # $30,000 > $25,000
            stop_price=195.0,
        ),
        portfolio,
    )
    assert not dec_cap.approved
    assert "MAX_ORDER_NOTIONAL_EXCEEDED" in dec_cap.reason_codes


def test_compile_trader_variants_and_allow_shorting() -> None:
    prompt = (
        "Max order $10,000; daily drawdown 1.5%; limit open risk to 5%; "
        "never touch TSLA; allow shorting; human approval over $5k; max 6 open positions."
    )
    res = compile_natural_language_policy(prompt)

    assert res.policy.max_order_notional_usd == 10_000.0
    assert res.policy.max_daily_loss_pct == 1.5
    assert res.policy.max_total_heat_pct == 5.0
    assert res.policy.blocked_symbols == ["TSLA"]
    assert res.policy.allow_shorting is True
    assert res.policy.max_open_positions == 6
    assert res.human_confirm_above_usd == 5_000.0
    assert res.self_test_passed is True


def test_compile_percentage_order_cap_and_allowlist(tmp_path: Path) -> None:
    prompt = "On a $500k account, no order over 5% of portfolio, only allow SGOV, VOO, VTI."
    res = compile_natural_language_policy(prompt)

    assert res.allowed_symbols == ["SGOV", "VOO", "VTI"]
    assert "allowlist" in res.policy.sleeves
    assert res.policy.sleeves["allowlist"].max_order_notional_usd == 25_000.0
    assert res.self_test_passed is True

    svc = FirewallService.from_data_dir(tmp_path / "fw_alw", policy=res.policy, initialize_armed=True)
    portfolio = PortfolioSnapshot(account_id="TEST-2", nav_usd=500_000.0, cash_usd=500_000.0)

    # Allowlisted ETF inside $25k cap -> APPROVED
    dec_ok = svc.propose(
        TradeProposal(
            agent_id="agent-1",
            venue="ibkr",
            symbol="VOO",
            side=Side.BUY,
            order_type=OrderType.LIMIT,
            quantity=40,
            limit_price=500.0,  # $20,000 <= $25,000
        ),
        portfolio,
    )
    assert dec_ok.approved

    # Non-allowlisted ticker -> VETOED
    dec_unlisted = svc.propose(
        TradeProposal(
            agent_id="agent-1",
            venue="ibkr",
            symbol="NVDA",
            side=Side.BUY,
            order_type=OrderType.LIMIT,
            quantity=10,
            limit_price=130.0,
            stop_price=125.0,
        ),
        portfolio,
    )
    assert not dec_unlisted.approved
    assert "MAX_ORDER_NOTIONAL_EXCEEDED" in dec_unlisted.reason_codes


def test_compile_default_nav_warning_and_overlap_fail_closed() -> None:
    res_pct = compile_natural_language_policy("no order over 5% of portfolio")
    assert res_pct.policy.max_order_notional_usd == 5_000.0
    assert any("$100,000" in w for w in res_pct.warnings)
    assert res_pct.self_test_passed is True

    res_overlap = compile_natural_language_policy("only allow AAPL, TQQQ; block TQQQ")
    assert "TQQQ" in res_overlap.policy.blocked_symbols
    assert "TQQQ" not in res_overlap.allowed_symbols
    assert any("fail-closed" in w.lower() for w in res_overlap.warnings)
    assert res_overlap.self_test_passed is True

    res_empty = compile_natural_language_policy("")
    assert res_empty.extracted_rules == []
    assert len(res_empty.warnings) >= 1
    assert res_empty.self_test_passed is True


def test_run_safety_benchmark_25_scenarios() -> None:
    report = run_safety_benchmark()

    assert report.total_scenarios == 25
    assert report.attacks_total == 20
    assert report.attacks_blocked == 20
    assert report.block_rate_pct == 100.0
    assert report.legit_total == 5
    assert report.legit_approved == 5
    assert report.false_positive_rate_pct == 0.0
    assert report.avg_latency_ms >= 0.0
    assert report.p99_latency_ms >= 0.0
    assert report.audit_chain_valid is True
    assert report.audit_entry_count > 0
    assert len(report.results) == 25
    assert all(r.passed for r in report.results)

    by_id = {r.scenario_id: r for r in report.results}
    assert "MARKET_ORDER_FORBIDDEN" in by_id["PI-01"].reason_codes
    assert "MISSING_REFERENCE_PRICE" in by_id["PI-05"].reason_codes
    assert "MAX_ORDER_NOTIONAL_EXCEEDED" in by_id["FF-01"].reason_codes
    assert "INVALID_ORDER_QUANTITY" in by_id["FF-04"].reason_codes
    assert "INSUFFICIENT_CASH" in by_id["FF-05"].reason_codes
    assert "MISSING_STOP_LOSS" in by_id["RC-01"].reason_codes
    assert "INVALID_STOP_LOSS_DIRECTION" in by_id["RC-02"].reason_codes
    assert "KELLY_POSITION_SIZE_EXCEEDED" in by_id["RC-03"].reason_codes
    assert "MAX_TOTAL_HEAT_EXCEEDED" in by_id["RC-04"].reason_codes
    assert "DAILY_LOSS_LIMIT_BREACHED" in by_id["RC-05"].reason_codes
    assert "SYMBOL_BLOCKED" in by_id["RI-01"].reason_codes
    assert "SHORTING_NOT_ALLOWED" in by_id["RI-02"].reason_codes
    assert "MAX_GROSS_EXPOSURE_EXCEEDED" in by_id["RI-03"].reason_codes
    assert "MAX_ORDER_NOTIONAL_EXCEEDED" in by_id["RI-04"].reason_codes
    assert any(
        c in {"ATTESTATION_REPLAY_DETECTED", "NONCE_ALREADY_SPENT"}
        for c in by_id["RI-05"].reason_codes
    )

    for ok_id in ("OK-01", "OK-02", "OK-03", "OK-04", "OK-05"):
        assert by_id[ok_id].actual_outcome == "APPROVED"
        assert by_id[ok_id].reason_codes == []


def test_cli_benchmark_text_and_json(capsys) -> None:
    cli_main = pytest.importorskip("clearfills.cli").main
    rc_text = cli_main(["benchmark"])
    assert rc_text == 0
    out_text = capsys.readouterr().out
    assert "20/20 (100.0%)" in out_text
    assert "5/5 (0.0% false positives)" in out_text
    assert "p99" in out_text

    rc_json = cli_main(["benchmark", "--json"])
    assert rc_json == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_scenarios"] == 25
    assert payload["attacks_blocked"] == 20
    assert payload["legit_approved"] == 5
    assert payload["block_rate_pct"] == 100.0
    assert payload["false_positive_rate_pct"] == 0.0


def test_cli_compile_policy_text_json_and_output(tmp_path: Path, capsys) -> None:
    cli_main = pytest.importorskip("clearfills.cli").main
    rules = "Cap orders at $25k, stop trading if down 2% today, max heat 6%, block TQQQ, SQQQ"

    rc_text = cli_main(["compile-policy", rules])
    assert rc_text == 0
    out_text = capsys.readouterr().out
    assert "max_order_notional_usd" in out_text
    assert "100% enforcement verified" in out_text

    out_yaml = tmp_path / "compiled_policy.yaml"
    rc_json = cli_main(["compile-policy", rules, "--json", "--output", str(out_yaml)])
    assert rc_json == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["self_test_passed"] is True
    assert payload["policy"]["max_order_notional_usd"] == 25_000.0
    assert payload["policy"]["max_daily_loss_pct"] == 2.0
    assert payload["policy"]["max_total_heat_pct"] == 6.0
    assert out_yaml.is_file()

    loaded = RiskPolicy.from_yaml(out_yaml)
    assert loaded.max_order_notional_usd == 25_000.0
    assert loaded.blocked_symbols == ["TQQQ", "SQQQ"]
