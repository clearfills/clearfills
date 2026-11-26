"""Comprehensive tests for Security Hardening Track 1:
- Aligned RiskPolicy defaults & concentration/cumulative/rate caps
- Gap 1: Trusted PortfolioProvider, staleness fail-closed, server clock boundary, Kelly confidence cap
- Gap 5: Real RFC 8785 (JCS) canonical JSON test vectors & split-key Ed25519 AttestationVerifier
- Gap 7: Ed25519-signed & checkpointed hash-chain AuditLedger with tail-truncation detection
- Upgraded Policy Regression & Bypass Suite (29 scenarios)
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from clearfills_firewall import (
    SUITE_TITLE,
    AttestationAuthority,
    AttestationVerifier,
    AuditLedger,
    FirewallService,
    KillSwitch,
    LossSaleRecord,
    OrderType,
    PortfolioSnapshot,
    Position,
    RiskFirewall,
    RiskPolicy,
    Side,
    SimulatedPaperPortfolioProvider,
    StaticTrustedPortfolioProvider,
    TradeProposal,
    canonical_json,
    canonical_json_bytes,
    canonical_order_hash,
    create_app,
    handle_jsonrpc_request,
    run_policy_regression_suite,
    run_stdio_server,
)

_ET = ZoneInfo("America/New_York")


def _armed_ks(tmp_path: Path, name: str = "ks.json") -> KillSwitch:
    ks = KillSwitch(tmp_path / name)
    ks.initialize_armed(actor="test-ops", reason="armed for hardening tests")
    return ks


# ---------------------------------------------------------------------------
# 1. Policy Defaults & Concentration / Cumulative Notional / Order Rate Caps
# ---------------------------------------------------------------------------


def test_aligned_risk_policy_defaults() -> None:
    policy = RiskPolicy()
    assert policy.max_risk_per_trade_pct == 1.5
    assert policy.max_daily_loss_pct == 3.0
    assert policy.max_position_concentration_pct == 20.0
    assert policy.max_daily_cumulative_notional_usd == 200_000.0
    assert policy.max_orders_per_minute == 10
    assert policy.enforce_trusted_kelly is True


def test_position_concentration_cap_and_risk_reducing_close_allowed(tmp_path: Path) -> None:
    fw = RiskFirewall(
        policy=RiskPolicy(
            max_position_concentration_pct=20.0,
            max_order_notional_usd=100_000.0,
            enforce_kelly_sizing=False,
        ),
        kill_switch=_armed_ks(tmp_path),
    )
    # Existing $15k AAPL on $100k NAV = 15%
    pf = PortfolioSnapshot(
        account_id="ACC-1",
        nav_usd=100_000.0,
        cash_usd=85_000.0,
        open_positions=[
            Position(
                symbol="AAPL",
                venue="ibkr",
                quantity=75.0,
                avg_entry_price=200.0,
                current_price=200.0,
                stop_price=195.0,
            )
        ],
    )

    # Adding $10k AAPL -> $25k = 25% > 20% -> VETOED
    add_prop = TradeProposal(
        agent_id="agent-1",
        venue="ibkr",
        symbol="AAPL",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=50.0,
        limit_price=200.0,
        stop_price=196.0,
    )
    dec_veto = fw.evaluate_proposal(add_prop, pf)
    assert dec_veto.approved is False
    assert "MAX_POSITION_CONCENTRATION_EXCEEDED" in dec_veto.reason_codes
    assert dec_veto.metrics["projected_position_concentration_pct"] == pytest.approx(25.0)

    # Even if existing position is already 30% of NAV, a risk-reducing SELL MUST be allowed!
    over_pf = PortfolioSnapshot(
        account_id="ACC-1",
        nav_usd=100_000.0,
        cash_usd=70_000.0,
        open_positions=[
            Position(
                symbol="AAPL",
                venue="ibkr",
                quantity=150.0,
                avg_entry_price=200.0,
                current_price=200.0,
                stop_price=195.0,
            )
        ],
    )
    close_prop = TradeProposal(
        agent_id="agent-1",
        venue="ibkr",
        symbol="AAPL",
        side=Side.SELL,
        order_type=OrderType.LIMIT,
        quantity=150.0,
        limit_price=200.0,
    )
    dec_close = fw.evaluate_proposal(close_prop, over_pf)
    assert dec_close.approved is True
    assert "MAX_POSITION_CONCENTRATION_EXCEEDED" not in dec_close.reason_codes


def test_daily_cumulative_notional_anti_salami_slicing_and_utc_day_rollover(tmp_path: Path) -> None:
    day1 = datetime(2026, 11, 24, 14, 0, 0, tzinfo=timezone.utc)
    day2 = datetime(2026, 11, 25, 14, 0, 0, tzinfo=timezone.utc)
    current_time = [day1]

    fw = RiskFirewall(
        policy=RiskPolicy(
            max_order_notional_usd=50_000.0,
            max_daily_cumulative_notional_usd=100_000.0,
            max_position_concentration_pct=100.0,
            enforce_kelly_sizing=False,
        ),
        kill_switch=_armed_ks(tmp_path),
        clock=lambda: current_time[0],
    )
    pf = PortfolioSnapshot(account_id="ACC-2", nav_usd=1_000_000.0, cash_usd=1_000_000.0)

    for sym in ("AAPL", "MSFT"):
        d = fw.evaluate_proposal(
            TradeProposal(
                agent_id="slicer",
                venue="ibkr",
                symbol=sym,
                side=Side.BUY,
                quantity=200.0,
                limit_price=200.0,  # $40k each -> $80k cumulative
                stop_price=195.0,
            ),
            pf,
        )
        assert d.approved is True

    # 3rd order pushes cumulative to $110k > $100k -> VETOED
    d_veto = fw.evaluate_proposal(
        TradeProposal(
            agent_id="slicer",
            venue="ibkr",
            symbol="GOOGL",
            side=Side.BUY,
            quantity=150.0,
            limit_price=200.0,  # $30k -> $110k > $100k
            stop_price=195.0,
        ),
        pf,
    )
    assert d_veto.approved is False
    assert "MAX_DAILY_CUMULATIVE_NOTIONAL_EXCEEDED" in d_veto.reason_codes

    # Next UTC day -> cumulative resets -> APPROVED
    current_time[0] = day2
    d_next_day = fw.evaluate_proposal(
        TradeProposal(
            agent_id="slicer",
            venue="ibkr",
            symbol="GOOGL",
            side=Side.BUY,
            quantity=150.0,
            limit_price=200.0,
            stop_price=195.0,
        ),
        pf,
    )
    assert d_next_day.approved is True


def test_order_rate_limit_sliding_60s_window(tmp_path: Path) -> None:
    t0 = datetime(2026, 11, 24, 15, 0, 0, tzinfo=timezone.utc)
    now_ref = [t0]

    fw = RiskFirewall(
        policy=RiskPolicy(
            max_orders_per_minute=3,
            max_daily_cumulative_notional_usd=500_000.0,
            enforce_kelly_sizing=False,
        ),
        kill_switch=_armed_ks(tmp_path),
        clock=lambda: now_ref[0],
    )
    pf = PortfolioSnapshot(
        account_id="ACC-3",
        nav_usd=500_000.0,
        cash_usd=500_000.0,
        open_positions=[
            Position(
                symbol="AAPL",
                venue="ibkr",
                quantity=50.0,
                avg_entry_price=200.0,
                current_price=200.0,
                stop_price=195.0,
            )
        ],
    )

    for i in range(3):
        now_ref[0] = t0 + timedelta(seconds=i * 5)
        d = fw.evaluate_proposal(
            TradeProposal(
                agent_id="burst-bot",
                venue="ibkr",
                symbol=f"SYM{i}",
                side=Side.BUY,
                quantity=10.0,
                limit_price=100.0,
                stop_price=95.0,
            ),
            pf,
        )
        assert d.approved is True

    # 4th order within 60s -> ORDER_RATE_EXCEEDED
    now_ref[0] = t0 + timedelta(seconds=20)
    d_rate = fw.evaluate_proposal(
        TradeProposal(
            agent_id="burst-bot",
            venue="ibkr",
            symbol="SYM9",
            side=Side.BUY,
            quantity=10.0,
            limit_price=100.0,
            stop_price=95.0,
        ),
        pf,
    )
    assert d_rate.approved is False
    assert "ORDER_RATE_EXCEEDED" in d_rate.reason_codes

    # Risk-reducing SELL is still permitted even when rate limit is saturated
    d_sell = fw.evaluate_proposal(
        TradeProposal(
            agent_id="burst-bot",
            venue="ibkr",
            symbol="AAPL",
            side=Side.SELL,
            quantity=50.0,
            limit_price=200.0,
        ),
        pf,
    )
    assert d_sell.approved is True

    # After 61 seconds, oldest orders expire from sliding window -> APPROVED again
    now_ref[0] = t0 + timedelta(seconds=61)
    d_after = fw.evaluate_proposal(
        TradeProposal(
            agent_id="burst-bot",
            venue="ibkr",
            symbol="SYM10",
            side=Side.BUY,
            quantity=10.0,
            limit_price=100.0,
            stop_price=95.0,
        ),
        pf,
    )
    assert d_after.approved is True


# ---------------------------------------------------------------------------
# 2. Gap 1: Trusted PortfolioProvider, Staleness, Server Clock & Kelly Cap
# ---------------------------------------------------------------------------


def test_trusted_portfolio_provider_ignores_spoofed_caller_portfolio_and_enforces_staleness(
    tmp_path: Path,
) -> None:
    t_now = datetime(2026, 11, 24, 15, 0, 0, tzinfo=timezone.utc)
    now_ref = [t_now]

    # Authoritative server portfolio has ONLY $5,000 cash and $50,000 NAV
    real_snapshot = PortfolioSnapshot(
        account_id="REAL-IBKR",
        nav_usd=50_000.0,
        cash_usd=5_000.0,
        timestamp=t_now,
    )
    provider = StaticTrustedPortfolioProvider(real_snapshot)
    svc = FirewallService.from_data_dir(
        tmp_path / "fw_trusted",
        policy=RiskPolicy(enforce_kelly_sizing=False),
        initialize_armed=True,
        portfolio_provider=provider,
        max_snapshot_age_seconds=30.0,
        clock=lambda: now_ref[0],
    )

    # Attacker submits a spoofed portfolio claiming $10M NAV and $10M cash
    spoofed_portfolio_dict = {
        "account_id": "SPOOFED",
        "nav_usd": 10_000_000.0,
        "cash_usd": 10_000_000.0,
        "open_positions": [],
    }
    proposal_dict = {
        "agent_id": "rogue-agent",
        "venue": "ibkr",
        "symbol": "AAPL",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 40.0,
        "limit_price": 200.0,  # $8,000 > real $5,000 cash!
        "stop_price": 195.0,
    }

    # Test via FastAPI HTTP /v1/propose
    client = TestClient(create_app(svc))
    resp = client.post(
        "/v1/propose",
        json={"proposal": proposal_dict, "portfolio": spoofed_portfolio_dict},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approved"] is False
    assert "INSUFFICIENT_CASH" in body["reason_codes"]
    assert body["metrics"]["nav_usd"] == 50_000.0
    assert body["metrics"]["portfolio_source"] == "trusted_provider"

    # Test via MCP JSON-RPC propose_trade (even omitting portfolio altogether)
    mcp_resp = handle_jsonrpc_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "propose_trade",
                "arguments": {"proposal": proposal_dict, "portfolio": spoofed_portfolio_dict},
            },
        },
        svc,
    )
    assert mcp_resp is not None
    mcp_dec = json.loads(mcp_resp["result"]["content"][0]["text"])
    assert mcp_dec["approved"] is False
    assert "INSUFFICIENT_CASH" in mcp_dec["reason_codes"]
    assert mcp_dec["metrics"]["nav_usd"] == 50_000.0

    # Advance server clock 45s -> snapshot is now stale (> 30s) -> fail closed!
    now_ref[0] = t_now + timedelta(seconds=45)
    stale_resp = client.post("/v1/propose", json={"proposal": proposal_dict})
    assert stale_resp.status_code == 200
    stale_body = stale_resp.json()
    assert stale_body["approved"] is False
    assert stale_body["reason_codes"] == ["STALE_PORTFOLIO_SNAPSHOT"]


def test_simulated_paper_portfolio_provider_accounting() -> None:
    t0 = datetime(2026, 11, 24, 15, 0, 0, tzinfo=timezone.utc)
    paper = SimulatedPaperPortfolioProvider(
        account_id="PAPER-99",
        nav_usd=100_000.0,
        cash_usd=100_000.0,
        clock=lambda: t0,
    )
    snap0 = paper.get_snapshot()
    assert snap0.cash_usd == 100_000.0
    assert snap0.open_position_count == 0

    snap1 = paper.record_fill(
        symbol="NVDA",
        venue="paper",
        side=Side.BUY,
        quantity=100.0,
        price=120.0,
        stop_price=115.0,
    )
    assert snap1.cash_usd == pytest.approx(88_000.0)
    assert snap1.held_quantity("NVDA") == pytest.approx(100.0)
    assert snap1.session_entries == 1


def test_http_and_mcp_never_trust_caller_created_at(tmp_path: Path) -> None:
    # Server clock is Friday 15:45 ET (blocked by BOTH Friday rule and 15:30 ET cutoff)
    fri_after_hours = datetime(2026, 11, 27, 15, 45, tzinfo=_ET).astimezone(timezone.utc)
    mon_spoofed = datetime(2026, 11, 23, 10, 30, tzinfo=_ET).astimezone(timezone.utc)

    svc = FirewallService.from_data_dir(
        tmp_path / "fw_clock",
        policy=RiskPolicy(
            block_last_session_of_week=True,
            no_entries_after_et="15:30",
            enforce_kelly_sizing=False,
        ),
        initialize_armed=True,
        clock=lambda: fri_after_hours,
    )
    pf_dict = {"account_id": "ACC-CLK", "nav_usd": 100_000.0, "cash_usd": 100_000.0}
    spoofed_prop_dict = {
        "agent_id": "clock-spoofer",
        "venue": "ibkr",
        "symbol": "AAPL",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 25.0,
        "limit_price": 200.0,
        "stop_price": 195.0,
        "created_at": mon_spoofed.isoformat(),
    }

    # HTTP /v1/propose must overwrite created_at and VETO
    client = TestClient(create_app(svc))
    http_res = client.post("/v1/propose", json={"proposal": spoofed_prop_dict, "portfolio": pf_dict}).json()
    assert http_res["approved"] is False
    assert "LAST_SESSION_OF_WEEK_BLOCKED" in http_res["reason_codes"]
    assert "SESSION_CUTOFF_EXCEEDED" in http_res["reason_codes"]

    # MCP propose_trade must also overwrite created_at and VETO
    mcp_resp = handle_jsonrpc_request(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "propose_trade",
                "arguments": {"proposal": spoofed_prop_dict, "portfolio": pf_dict},
            },
        },
        svc,
    )
    assert mcp_resp is not None
    mcp_res = json.loads(mcp_resp["result"]["content"][0]["text"])
    assert mcp_res["approved"] is False
    assert "LAST_SESSION_OF_WEEK_BLOCKED" in mcp_res["reason_codes"]
    assert "SESSION_CUTOFF_EXCEEDED" in mcp_res["reason_codes"]


def test_untrusted_confidence_kelly_capped_to_max_risk_per_trade(tmp_path: Path) -> None:
    fw = RiskFirewall(
        policy=RiskPolicy(
            max_risk_per_trade_pct=1.5,
            enforce_kelly_sizing=True,
            enforce_trusted_kelly=True,
        ),
        kill_switch=_armed_ks(tmp_path),
    )
    pf = PortfolioSnapshot(account_id="ACC-KELLY", nav_usd=100_000.0, cash_usd=100_000.0)
    # Agent passes confidence=0.9999 and 10:1 R:R trying to inflate Kelly sizing
    prop = TradeProposal(
        agent_id="hyperconfident-llm",
        venue="ibkr",
        symbol="NVDA",
        side=Side.BUY,
        quantity=100.0,
        limit_price=100.0,
        stop_price=99.0,  # $100 risk = 0.1% NAV
        target_price=110.0,  # 10:1 R:R -> raw quarter Kelly would be ~18.1%
        confidence=0.9999,
    )
    dec = fw.evaluate_proposal(prop, pf)
    assert dec.approved is True
    assert dec.metrics["effective_kelly_confidence"] == pytest.approx(0.75)
    # Effective Kelly cap is strictly bounded by max_risk_per_trade_pct (1.5%)
    assert dec.metrics["fractional_kelly_pct"] <= 1.5
    assert dec.metrics["max_qty_by_kelly"] <= dec.metrics["max_qty_by_risk"] + 1e-6


# ---------------------------------------------------------------------------
# 3. Gap 5: Real RFC 8785 (JCS) + Split-Key Ed25519 AttestationVerifier
# ---------------------------------------------------------------------------


def test_rfc8785_jcs_official_vectors() -> None:
    # Numbers (RFC 8785 Section 3.2.2.3 & Appendix B)
    assert canonical_json(0.0) == "0"
    assert canonical_json(-0.0) == "0"
    assert canonical_json(100.0) == "100"
    assert canonical_json(1e20) == "100000000000000000000"
    assert canonical_json(1e21) == "1e+21"
    assert canonical_json(1e-6) == "0.000001"
    assert canonical_json(1e-7) == "1e-7"
    assert canonical_json(333333333.33333329) == "333333333.3333333"
    assert canonical_json(1e30) == "1e+30"
    assert canonical_json(4.50) == "4.5"
    assert canonical_json(2e-3) == "0.002"
    assert canonical_json(0.000000000000000000000000001) == "1e-27"

    # Non-finite floats MUST be rejected
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            canonical_json_bytes({"x": bad})

    # String escaping (RFC 8785 Section 3.2.2.2)
    assert canonical_json("a/b") == '"a/b"'
    assert canonical_json("\b\t\n\f\r\"\\") == '"\\b\\t\\n\\f\\r\\"\\\\"'
    assert canonical_json("\x00\x1f") == '"\\u0000\\u001f"'
    assert canonical_json("€😀") == '"€😀"'

    # Official RFC 8785 Section 3.2.3 UTF-16 code-unit sorting test vector:
    # Note: U+1F600 (😀) encodes as UTF-16 surrogate pair 0xD83D 0xDE00,
    # which MUST sort BEFORE U+FB33 (\ufb33 = 0xFB33) in UTF-16 code-unit order!
    obj = {
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "\r": "Carriage Return",
        "1": "One",
        "\u0080": "Control",
        "\u20ac": "Euro Sign",
        "\U0001f600": "Emoji: Grinning Face",
        "\u00f6": "Latin Small Letter O With Diaeresis",
    }
    serialized = canonical_json(obj)
    expected = (
        '{"\\r":"Carriage Return",'
        '"1":"One",'
        '"\u0080":"Control",'
        '"\u00f6":"Latin Small Letter O With Diaeresis",'
        '"\u20ac":"Euro Sign",'
        '"\U0001f600":"Emoji: Grinning Face",'
        '"\ufb33":"Hebrew Letter Dalet With Dagesh"}'
    )
    assert serialized == expected

    # Equivalence between int and float representations
    assert canonical_json_bytes({"b": 100.0, "a": -0.0}) == canonical_json_bytes({"a": 0, "b": 100})


def test_split_key_ed25519_attestation_verifier_cannot_sign(tmp_path: Path) -> None:
    authority = AttestationAuthority(ttl_seconds=120)
    verifier = AttestationVerifier(
        authority.public_key_pem(),
        spent_nonces_path=tmp_path / "gateway_nonces.json",
    )

    # Structural split-key property: verifier has NO signing capability
    assert not hasattr(verifier, "issue")
    assert not hasattr(verifier, "_private_key")
    assert verifier.key_id == authority.key_id

    proposal = TradeProposal(
        agent_id="split-key-agent",
        venue="ibkr",
        symbol="AAPL",
        side=Side.BUY,
        quantity=50.0,
        limit_price=200.0,
        stop_price=195.0,
    )
    att = authority.issue(proposal)
    assert att.order_hash == canonical_order_hash(proposal)

    # Stateless verify succeeds without consuming nonce
    ok_stateless, reason_stateless = verifier.verify(att, proposal)
    assert ok_stateless is True and reason_stateless == "OK"

    # Tampered proposal fails verification without consuming nonce
    tampered = proposal.model_copy(update={"quantity": 500.0})
    ok_tamp, reason_tamp = verifier.verify_and_consume(att, tampered)
    assert ok_tamp is False and reason_tamp == "ORDER_HASH_MISMATCH"

    # First valid consume succeeds
    ok1, r1 = verifier.verify_and_consume(att, proposal)
    assert ok1 is True and r1 == "OK"

    # Second consume is blocked as replay
    ok2, r2 = verifier.verify_and_consume(att, proposal)
    assert ok2 is False and r2 == "ATTESTATION_REPLAY_DETECTED"

    # Verifier with a different public key rejects UNKNOWN_KEY_ID
    other_verifier = AttestationAuthority().verifier()
    ok_wrong, r_wrong = other_verifier.verify(att, proposal)
    assert ok_wrong is False and r_wrong == "UNKNOWN_KEY_ID"


# ---------------------------------------------------------------------------
# 4. Gap 7: Signed & Checkpointed Hash-Chain Ledger
# ---------------------------------------------------------------------------


def test_signed_checkpointed_ledger_detects_tamper_bad_sig_and_tail_truncation(
    tmp_path: Path,
) -> None:
    priv = Ed25519PrivateKey.generate()
    ledger_path = tmp_path / "signed_audit.jsonl"
    ledger = AuditLedger(ledger_path, private_key=priv)
    pub_pem = ledger.public_key_pem()
    assert pub_pem is not None

    e1 = ledger.append("PROPOSAL_APPROVED", "agent-a", {"symbol": "AAPL", "qty": 100.0})
    e2 = ledger.append("DISPATCH_ALLOWED", "agent-a", {"symbol": "AAPL", "qty": 100.0})
    e3 = ledger.append("PROPOSAL_VETOED", "agent-b", {"symbol": "TQQQ", "reason": "SYMBOL_BLOCKED"})

    assert e1.seq_no == 1 and e2.seq_no == 2 and e3.seq_no == 3
    assert e1.entry_signature is not None
    assert e3.entry_signature is not None

    cp = ledger.get_checkpoint()
    assert cp["seq_no"] == 3
    assert cp["head_hash"] == e3.entry_hash
    assert cp["head_sig"] == e3.entry_signature

    # Valid verification with checkpoint + public key
    ok, err, count = ledger.verify_chain(
        expected_min_seq=cp["seq_no"],
        expected_checkpoint_hash=cp["head_hash"],
        public_key_pem=pub_pem,
    )
    assert ok is True and err is None and count == 3

    # Growing beyond the checkpoint still verifies against the earlier checkpoint!
    e4 = ledger.append("KILL_SWITCH_TRIPPED", "ops", {"reason": "drill"})
    assert e4.seq_no == 4
    ok_grow, err_grow, count_grow = ledger.verify_chain(
        expected_min_seq=cp["seq_no"],
        expected_checkpoint_hash=cp["head_hash"],
        public_key_pem=pub_pem,
    )
    assert ok_grow is True and err_grow is None and count_grow == 4

    # Wrong public key MUST fail closed
    wrong_pub = AttestationAuthority().public_key_pem()
    ok_wrong_key, err_wrong_key, _ = ledger.verify_chain(public_key_pem=wrong_pub)
    assert ok_wrong_key is False
    assert err_wrong_key is not None and "signature" in err_wrong_key.lower()

    # Tail truncation attack: delete the last 2 entries (so only 2 remain < expected_min_seq=3)
    original_lines = ledger_path.read_text(encoding="utf-8").splitlines()
    ledger_path.write_text("\n".join(original_lines[:2]) + "\n", encoding="utf-8")

    # Without checkpoint, truncated prefix looks internally consistent...
    ok_no_cp, _, count_no_cp = ledger.verify_chain(public_key_pem=pub_pem)
    assert ok_no_cp is True and count_no_cp == 2

    # ...WITH checkpoint, tail truncation MUST fail closed!
    ok_trunc, err_trunc, count_trunc = ledger.verify_chain(
        expected_min_seq=cp["seq_no"],
        expected_checkpoint_hash=cp["head_hash"],
        public_key_pem=pub_pem,
    )
    assert ok_trunc is False
    assert err_trunc is not None and "truncation" in err_trunc.lower()
    assert count_trunc == 2


# ---------------------------------------------------------------------------
# 5. Policy Regression & Bypass Suite
# ---------------------------------------------------------------------------


def test_policy_regression_and_bypass_suite_all_pass() -> None:
    report = run_policy_regression_suite()
    assert report.suite_title == SUITE_TITLE == "Policy Regression & Bypass Suite"
    assert report.total_scenarios == 29
    assert report.attacks_total == 24
    assert report.attacks_blocked == 24
    assert report.block_rate_pct == 100.0
    assert report.legit_total == 5
    assert report.legit_approved == 5
    assert report.false_positive_rate_pct == 0.0
    assert report.audit_chain_valid is True
    assert all(r.passed for r in report.results)


# ---------------------------------------------------------------------------
# 6. Final Hardening: Secure Defaults, 61-Day Wash-Sale Window & Checkpoint Hook
# ---------------------------------------------------------------------------


def test_firewall_service_enforces_server_clock_by_default(tmp_path: Path) -> None:
    """FirewallService MUST default to enforce_server_clock=True and ignore spoofed created_at."""
    fri_after_hours = datetime(2026, 11, 27, 15, 45, tzinfo=_ET).astimezone(timezone.utc)
    mon_spoofed = datetime(2026, 11, 23, 10, 30, tzinfo=_ET).astimezone(timezone.utc)

    # Do NOT pass enforce_server_clock explicitly — default MUST be True
    svc = FirewallService.from_data_dir(
        tmp_path / "fw_default_clock",
        policy=RiskPolicy(
            block_last_session_of_week=True,
            no_entries_after_et="15:30",
            enforce_kelly_sizing=False,
        ),
        initialize_armed=True,
        clock=lambda: fri_after_hours,
    )
    assert svc.firewall.enforce_server_clock is True

    pf = PortfolioSnapshot(account_id="ACC-DEF-CLK", nav_usd=100_000.0, cash_usd=100_000.0)
    spoofed_prop = TradeProposal(
        agent_id="clock-spoofer",
        venue="ibkr",
        symbol="AAPL",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=25.0,
        limit_price=200.0,
        stop_price=195.0,
        created_at=mon_spoofed,
    )

    dec = svc.propose(spoofed_prop, pf)
    assert dec.approved is False
    assert "LAST_SESSION_OF_WEEK_BLOCKED" in dec.reason_codes
    assert "SESSION_CUTOFF_EXCEEDED" in dec.reason_codes


def test_mcp_server_ignores_caller_spoofed_portfolio_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_stdio_server MUST default to SimulatedPaperPortfolioProvider and ignore caller portfolio.nav_usd."""
    monkeypatch.delenv("CLEARFILLS_ALLOW_CALLER_PORTFOLIO", raising=False)
    t_now = datetime(2026, 11, 24, 15, 0, 0, tzinfo=timezone.utc)

    svc = FirewallService.from_data_dir(
        tmp_path / "fw_mcp_default_provider",
        policy=RiskPolicy(
            max_order_notional_usd=500_000.0,
            max_daily_cumulative_notional_usd=500_000.0,
            max_position_concentration_pct=100.0,
            enforce_kelly_sizing=False,
        ),
        initialize_armed=True,
        clock=lambda: t_now,
    )
    assert svc.portfolio_provider is None

    # Caller tries to spoof $10M NAV & $10M cash to buy $150k (exceeds default $100k paper portfolio)
    spoofed_portfolio = {
        "account_id": "SPOOFED-WHALE",
        "nav_usd": 10_000_000.0,
        "cash_usd": 10_000_000.0,
        "open_positions": [],
    }
    oversized_proposal = {
        "agent_id": "rogue-mcp-agent",
        "venue": "ibkr",
        "symbol": "AAPL",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 750.0,
        "limit_price": 200.0,  # $150,000 > $100,000 server-owned paper NAV/cash
        "stop_price": 199.0,
    }
    req = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "propose_trade",
            "arguments": {"proposal": oversized_proposal, "portfolio": spoofed_portfolio},
        },
    }

    stdin = io.StringIO(json.dumps(req) + "\n")
    stdout = io.StringIO()
    run_stdio_server(svc, stdin=stdin, stdout=stdout)

    assert isinstance(svc.portfolio_provider, SimulatedPaperPortfolioProvider)
    resp = json.loads(stdout.getvalue().strip())
    dec = json.loads(resp["result"]["content"][0]["text"])
    assert dec["approved"] is False
    assert "INSUFFICIENT_CASH" in dec["reason_codes"]
    assert dec["metrics"]["nav_usd"] == pytest.approx(100_000.0)
    assert dec["metrics"]["portfolio_source"] == "trusted_provider"


def test_real_61_day_date_based_wash_sale_window(tmp_path: Path) -> None:
    """BUY within ±30 calendar days of a LossSaleRecord is blocked; >30 days (35 days) is allowed."""
    now_dt = datetime(2026, 11, 25, 15, 0, 0, tzinfo=timezone.utc)
    sale_15d_ago = now_dt - timedelta(days=15)
    sale_35d_ago = now_dt - timedelta(days=35)

    svc = FirewallService.from_data_dir(
        tmp_path / "fw_wash_sale",
        policy=RiskPolicy(enforce_kelly_sizing=False),
        initialize_armed=True,
        clock=lambda: now_dt,
    )

    pf = PortfolioSnapshot(
        account_id="TAXABLE-MAIN",
        nav_usd=200_000.0,
        cash_usd=200_000.0,
        recent_loss_sales=[
            LossSaleRecord(
                symbol="AAPL",
                sold_at=sale_15d_ago,
                realized_loss_usd=-4_250.0,
                account_id="IRA-SPOUSE-01",
            ),
            LossSaleRecord(
                symbol="MSFT",
                sold_at=sale_35d_ago,
                realized_loss_usd=-3_100.0,
                account_id="TAXABLE-MAIN",
            ),
        ],
    )

    # AAPL sold at a loss 15 days ago -> BLOCKED with WASH_SALE_WINDOW_VIOLATION citing date & account
    aapl_buy = TradeProposal(
        agent_id="tax-agent",
        venue="ibkr",
        symbol="AAPL",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=25.0,
        limit_price=200.0,
        stop_price=195.0,
    )
    dec_aapl = svc.propose(aapl_buy, pf)
    assert dec_aapl.approved is False
    assert "WASH_SALE_WINDOW_VIOLATION" in dec_aapl.reason_codes
    matching_reasons = [r for r in dec_aapl.reasons if sale_15d_ago.date().isoformat() in r and "IRA-SPOUSE-01" in r]
    assert len(matching_reasons) == 1

    # MSFT sold at a loss 35 days ago (>30d) -> ALLOWED
    msft_buy = TradeProposal(
        agent_id="tax-agent",
        venue="ibkr",
        symbol="MSFT",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=20.0,
        limit_price=400.0,
        stop_price=390.0,
    )
    dec_msft = svc.propose(msft_buy, pf)
    assert dec_msft.approved is True
    assert "WASH_SALE_WINDOW_VIOLATION" not in dec_msft.reason_codes


def test_automatic_ledger_checkpoint_callback_fires_on_every_append(tmp_path: Path) -> None:
    """AuditLedger and FirewallService.from_data_dir emit (seq_no, head_hash, head_sig) on every append."""
    checkpoints: list[dict] = []
    svc = FirewallService.from_data_dir(
        tmp_path / "fw_checkpoint_hook",
        policy=RiskPolicy(enforce_kelly_sizing=False),
        initialize_armed=True,
        checkpoint_callback=checkpoints.append,
    )

    pf = PortfolioSnapshot(account_id="ACC-CP", nav_usd=100_000.0, cash_usd=100_000.0)
    prop = TradeProposal(
        agent_id="cp-agent",
        venue="ibkr",
        symbol="NVDA",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=20.0,
        limit_price=120.0,
        stop_price=115.0,
    )
    dec = svc.propose(prop, pf)
    assert dec.approved is True and dec.attestation is not None
    svc.dispatch_check(dec.attestation, prop)

    assert len(checkpoints) == 2
    entries = svc.ledger.read_entries()
    assert len(entries) == 2

    for idx, (cp, entry) in enumerate(zip(checkpoints, entries), start=1):
        assert cp["seq_no"] == idx == entry.seq
        assert cp["head_hash"] == entry.entry_hash
        assert cp["head_sig"] == entry.entry_signature
        assert cp["head_sig"] is not None

    # Failing callback must NOT corrupt or block local ledger append
    def _broken_callback(_cp: dict) -> None:
        raise RuntimeError("transient remote witness failure")

    priv = Ed25519PrivateKey.generate()
    resilient_ledger = AuditLedger(
        tmp_path / "resilient.jsonl",
        private_key=priv,
        checkpoint_callback=_broken_callback,
    )
    e1 = resilient_ledger.append("TEST_EVENT", "actor-1", {"ok": True})
    assert e1.seq_no == 1
    ok, err, count = resilient_ledger.verify_chain(public_key_pem=resilient_ledger.public_key_pem())
    assert ok is True and err is None and count == 1
