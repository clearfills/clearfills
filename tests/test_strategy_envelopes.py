"""Unit tests for Signed Strategy Envelopes, Live Equity-Curve Decay Auto-Kill, and 3 Named Risk Profiles."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from clearfills_firewall import (
    EnvelopeEvaluator,
    KillSwitch,
    OrderType,
    PortfolioSnapshot,
    RiskProfilePreset,
    Side,
    StrategyEnvelope,
    TradeProposal,
    compute_envelope_signature_hash,
    evaluate_proposal,
    list_risk_profiles,
    policy_from_profile,
)
from clearfills_firewall.envelopes import sign_envelope_ed25519, verify_envelope_ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _make_proposal(
    *,
    symbol: str = "SPY",
    side: Side = Side.BUY,
    order_type: OrderType = OrderType.MARKET,
    quantity: float = 10.0,
    limit_price: float | None = 500.0,
    stop_price: float | None = None,
    strategy_id: str = "mom_200dma",
) -> TradeProposal:
    return TradeProposal(
        agent_id="quant-cpu-worker",
        venue="ibkr",
        symbol=symbol,
        side=side,
        order_type=order_type,
        quantity=quantity,
        limit_price=limit_price,
        stop_price=stop_price,
        strategy_id=strategy_id,
    )


def _make_envelope(**overrides: object) -> StrategyEnvelope:
    base = {
        "strategy_id": "mom_200dma",
        "name": "US Equity Momentum",
        "profile": RiskProfilePreset.SYSTEMATIC_QUANT,
        "allowed_symbols": ["SPY", "QQQ", "IWM"],
        "blocked_symbols": ["GME"],
        "max_order_notional_usd": 25_000.0,
        "max_strategy_notional_usd": 100_000.0,
        "max_daily_loss_usd": 2_500.0,
        "max_orders_per_minute": 10,
        "allow_market_orders": True,
        "require_stop_loss": False,
        "decay_ma_window": 5,
        "max_drawdown_pct": 10.0,
        "signed_by": "human:philipp@quant.io",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        "active": True,
    }
    base.update(overrides)
    return StrategyEnvelope(**base)


def test_three_named_risk_profiles_presets() -> None:
    holdco = policy_from_profile("long_term_holdco")
    assert holdco.allow_market_orders is False
    assert holdco.require_stop_loss is False
    assert holdco.allow_shorting is False
    assert holdco.max_gross_exposure_pct == 100.0

    swing = policy_from_profile(RiskProfilePreset.ACTIVE_SWING)
    assert swing.allow_market_orders is False
    assert swing.require_stop_loss is True
    assert swing.max_risk_per_trade_pct == 1.5
    assert swing.max_daily_loss_pct == 3.0

    quant = policy_from_profile("SYSTEMATIC_QUANT")
    assert quant.allow_market_orders is True
    assert quant.require_stop_loss is False
    assert quant.max_gross_exposure_pct == 150.0
    assert quant.allow_shorting is True

    with pytest.raises(ValueError, match="Unknown risk profile"):
        policy_from_profile("yolo_100x")

    catalog = list_risk_profiles()
    ids = [p["id"] for p in catalog]
    assert ids == ["long_term_holdco", "active_swing", "systematic_quant"]
    assert catalog[0]["envelope_defaults"]["max_position_pct"] == 25.0
    assert catalog[0]["envelope_defaults"]["max_gross_exposure_pct"] == 100.0
    assert catalog[1]["envelope_defaults"]["max_risk_per_trade_pct"] == 1.5
    assert catalog[1]["envelope_defaults"]["max_daily_loss_pct"] == 3.0
    assert catalog[1]["envelope_defaults"]["max_gross_exposure_pct"] == 100.0
    assert catalog[2]["envelope_defaults"]["max_orders_per_minute"] == 10
    assert catalog[2]["envelope_defaults"]["max_gross_exposure_pct"] == 150.0
    # Verify unit consistency between envelope_defaults and RiskPolicy
    assert catalog[0]["envelope_defaults"]["max_gross_exposure_pct"] == catalog[0]["policy"]["max_gross_exposure_pct"]
    assert catalog[1]["envelope_defaults"]["max_risk_per_trade_pct"] == catalog[1]["policy"]["max_risk_per_trade_pct"]
    assert catalog[1]["envelope_defaults"]["max_daily_loss_pct"] == catalog[1]["policy"]["max_daily_loss_pct"]
    assert catalog[2]["envelope_defaults"]["max_gross_exposure_pct"] == catalog[2]["policy"]["max_gross_exposure_pct"]


def test_profiles_integrate_with_evaluate_proposal(tmp_path) -> None:
    ks = KillSwitch(tmp_path / "ks.json")
    ks.initialize_armed()
    portfolio = PortfolioSnapshot(nav_usd=100_000.0, cash_usd=100_000.0)

    # Long-term holdco: limit order without stop-loss passes; market order vetoed
    holdco = policy_from_profile("long_term_holdco")
    limit_no_stop = _make_proposal(symbol="MSFT", order_type=OrderType.LIMIT, quantity=10, limit_price=400.0)
    assert evaluate_proposal(limit_no_stop, portfolio, holdco, ks).approved is True

    market_order = _make_proposal(symbol="MSFT", order_type=OrderType.MARKET, quantity=10, limit_price=400.0)
    dec_holdco_mkt = evaluate_proposal(market_order, portfolio, holdco, ks)
    assert dec_holdco_mkt.approved is False
    assert "MARKET_ORDER_FORBIDDEN" in dec_holdco_mkt.reason_codes

    # Active swing: limit order without stop-loss is vetoed
    swing = policy_from_profile("active_swing")
    dec_swing = evaluate_proposal(limit_no_stop, portfolio, swing, ks)
    assert dec_swing.approved is False
    assert "MISSING_STOP_LOSS" in dec_swing.reason_codes

    # Systematic quant: market order without stop-loss is approved
    quant = policy_from_profile("systematic_quant")
    dec_quant = evaluate_proposal(market_order, portfolio, quant, ks)
    assert dec_quant.approved is True


def test_envelope_signature_and_happy_path() -> None:
    env = _make_envelope(allowed_symbols=[" spy ", "qqq"], blocked_symbols=[" gme "])
    assert env.allowed_symbols == ["SPY", "QQQ"]
    assert env.blocked_symbols == ["GME"]
    assert len(env.signature_hash) == 64
    assert env.signature_hash == compute_envelope_signature_hash(env)

    evaluator = EnvelopeEvaluator()
    now = datetime(2026, 11, 25, 15, 0, 0, tzinfo=timezone.utc)
    verdict = evaluator.evaluate(
        _make_proposal(symbol="SPY", quantity=10, limit_price=500.0),
        env,
        recent_order_timestamps=[now - timedelta(seconds=10), now - timedelta(seconds=30)],
        equity_curve=[100_000, 101_000, 102_000, 103_000, 104_000],
        current_strategy_notional_usd=20_000.0,
        daily_pnl_usd=-500.0,
        now=now,
    )
    assert verdict.allowed is True
    assert verdict.auto_kill_triggered is False
    assert verdict.auto_flatten_recommended is False
    assert verdict.violation_codes == []
    assert verdict.metrics["eval_latency_ms"] < 5.0


def test_envelope_inactive_and_expired() -> None:
    evaluator = EnvelopeEvaluator()
    now = datetime(2026, 11, 25, 15, 0, 0, tzinfo=timezone.utc)

    inactive_env = _make_envelope(active=False)
    v_inactive = evaluator.evaluate(_make_proposal(), inactive_env, now=now)
    assert v_inactive.allowed is False
    assert "ENVELOPE_INACTIVE" in v_inactive.violation_codes

    expired_env = _make_envelope(expires_at=(now - timedelta(seconds=1)).isoformat())
    v_expired = evaluator.evaluate(_make_proposal(), expired_env, now=now)
    assert v_expired.allowed is False
    assert "ENVELOPE_EXPIRED" in v_expired.violation_codes

    bad_exp_env = _make_envelope(expires_at="not-a-timestamp")
    v_bad = evaluator.evaluate(_make_proposal(), bad_exp_env, now=now)
    assert v_bad.allowed is False
    assert "ENVELOPE_EXPIRED" in v_bad.violation_codes


def test_envelope_symbols_order_type_and_stop_loss() -> None:
    evaluator = EnvelopeEvaluator()
    env = _make_envelope(
        allowed_symbols=["SPY", "QQQ"],
        blocked_symbols=["GME"],
        allow_market_orders=False,
        require_stop_loss=True,
    )

    v_not_allowed = evaluator.evaluate(
        _make_proposal(symbol="NVDA", order_type=OrderType.MARKET, stop_price=None),
        env,
    )
    assert v_not_allowed.allowed is False
    assert "ENVELOPE_SYMBOL_NOT_ALLOWED" in v_not_allowed.violation_codes
    assert "ENVELOPE_MARKET_ORDER_FORBIDDEN" in v_not_allowed.violation_codes
    assert "ENVELOPE_STOP_LOSS_REQUIRED" in v_not_allowed.violation_codes

    # Empty allowed_symbols allows any symbol except blocked_symbols
    open_env = _make_envelope(allowed_symbols=[], blocked_symbols=["GME"])
    assert evaluator.evaluate(_make_proposal(symbol="NVDA"), open_env).allowed is True
    v_blocked = evaluator.evaluate(_make_proposal(symbol="GME"), open_env)
    assert v_blocked.allowed is False
    assert "ENVELOPE_SYMBOL_NOT_ALLOWED" in v_blocked.violation_codes


def test_envelope_notional_and_daily_loss_caps() -> None:
    evaluator = EnvelopeEvaluator()
    env = _make_envelope(
        max_order_notional_usd=10_000.0,
        max_strategy_notional_usd=25_000.0,
        max_daily_loss_usd=1_000.0,
    )

    # Order notional exceeds cap
    v_order = evaluator.evaluate(_make_proposal(quantity=30, limit_price=500.0), env)
    assert v_order.allowed is False
    assert "ENVELOPE_NOTIONAL_EXCEEDED" in v_order.violation_codes

    # Aggregate strategy notional exceeds cap
    v_agg = evaluator.evaluate(
        _make_proposal(quantity=15, limit_price=500.0),
        env,
        current_strategy_notional_usd=20_000.0,
    )
    assert v_agg.allowed is False
    assert "ENVELOPE_NOTIONAL_EXCEEDED" in v_agg.violation_codes

    # Daily loss breached
    v_loss = evaluator.evaluate(
        _make_proposal(quantity=5, limit_price=500.0),
        env,
        daily_pnl_usd=-1_000.0,
    )
    assert v_loss.allowed is False
    assert "ENVELOPE_DAILY_LOSS_BREACHED" in v_loss.violation_codes


def test_envelope_runaway_loop_throttle() -> None:
    evaluator = EnvelopeEvaluator()
    now = datetime(2026, 11, 25, 15, 0, 0, tzinfo=timezone.utc)
    env = _make_envelope(max_orders_per_minute=3)

    # 2 orders in last 60s + 5 old orders (>60s ago) -> allowed
    timestamps = [
        now - timedelta(seconds=120),
        now - timedelta(seconds=90),
        now - timedelta(seconds=61),
        (now - timedelta(seconds=20)).timestamp(),
        (now - timedelta(seconds=5)).isoformat(),
    ]
    v_ok = evaluator.evaluate(_make_proposal(), env, recent_order_timestamps=timestamps, now=now)
    assert v_ok.allowed is True
    assert v_ok.metrics["orders_in_last_minute"] == 2

    # 3 orders in last 60s -> runaway-loop throttle tripped!
    timestamps.append(now - timedelta(seconds=1))
    v_throttled = evaluator.evaluate(_make_proposal(), env, recent_order_timestamps=timestamps, now=now)
    assert v_throttled.allowed is False
    assert "ENVELOPE_ORDER_RATE_EXCEEDED" in v_throttled.violation_codes
    assert v_throttled.auto_kill_triggered is False


def test_envelope_equity_curve_decay_200dma_auto_kill() -> None:
    evaluator = EnvelopeEvaluator()
    env = _make_envelope(decay_ma_window=200, max_drawdown_pct=None)

    # 199 points at 100k, last point drops to 98k -> below 200-DMA (99,990)
    curve_decay = [100_000.0] * 199 + [98_000.0]
    verdict = evaluator.evaluate(_make_proposal(), env, equity_curve=curve_decay)
    assert verdict.allowed is False
    assert verdict.auto_kill_triggered is True
    assert verdict.auto_flatten_recommended is True
    assert "ENVELOPE_EQUITY_CURVE_DECAY" in verdict.violation_codes
    assert verdict.metrics["decay_sma"] == pytest.approx(99_990.0)

    # Healthy uptrend stays above 200-DMA
    curve_healthy = [100_000.0 + i * 10.0 for i in range(200)]
    verdict_ok = evaluator.evaluate(_make_proposal(), env, equity_curve=curve_healthy)
    assert verdict_ok.allowed is True
    assert verdict_ok.auto_kill_triggered is False
    assert verdict_ok.auto_flatten_recommended is False

    # Fewer than 200 points does not prematurely trigger 200-DMA decay
    short_curve = [100_000.0, 99_000.0]
    verdict_short = evaluator.evaluate(_make_proposal(), env, equity_curve=short_curve)
    assert verdict_short.allowed is True


def test_envelope_max_drawdown_auto_kill() -> None:
    evaluator = EnvelopeEvaluator()
    env = _make_envelope(decay_ma_window=None, max_drawdown_pct=8.0)

    # Peak 120k -> live 110k = 8.33% drawdown >= 8.0%
    curve = [100_000.0, 120_000.0, 115_000.0, 110_000.0]
    verdict = evaluator.evaluate(_make_proposal(), env, equity_curve=curve)
    assert verdict.allowed is False
    assert verdict.auto_kill_triggered is True
    assert verdict.auto_flatten_recommended is True
    assert "ENVELOPE_MAX_DRAWDOWN_BREACHED" in verdict.violation_codes
    assert verdict.metrics["drawdown_pct"] == pytest.approx(8.3333, abs=0.01)


def test_envelope_evaluator_sub_millisecond_latency() -> None:
    evaluator = EnvelopeEvaluator()
    env = _make_envelope(decay_ma_window=200, max_drawdown_pct=15.0)
    proposal = _make_proposal()
    now = datetime.now(timezone.utc)
    recent = [now - timedelta(seconds=i * 5) for i in range(5)]
    curve = [100_000.0 + i * 5.0 for i in range(200)]

    start = time.perf_counter()
    for _ in range(100):
        v = evaluator.evaluate(proposal, env, recent, curve, now=now)
        assert v.allowed is True
    avg_ms = ((time.perf_counter() - start) * 1000.0) / 100.0
    assert avg_ms < 1.0, f"Expected <1ms per evaluation, got {avg_ms:.3f}ms"


def test_envelope_risk_reducing_position_close_allowed_at_95_pct_cap() -> None:
    evaluator = EnvelopeEvaluator()
    env = _make_envelope(
        max_order_notional_usd=25_000.0,
        max_strategy_notional_usd=100_000.0,
    )

    # Strategy is at 95% of its notional cap ($95,000 / $100,000; long 190 SPY @ $500)
    # 1. Adding risk (BUY 20 = $10k -> $105k) is blocked
    v_add = evaluator.evaluate(
        _make_proposal(side=Side.BUY, quantity=20, limit_price=500.0),
        env,
        current_strategy_notional_usd=95_000.0,
        current_position_qty=190.0,
    )
    assert v_add.allowed is False
    assert "ENVELOPE_NOTIONAL_EXCEEDED" in v_add.violation_codes
    assert v_add.metrics["is_reducing"] is False

    # 2. Flattening the full long position (SELL 190 = $95k) MUST be allowed (auto-detected via current_position_qty)
    v_flatten = evaluator.evaluate(
        _make_proposal(side=Side.SELL, quantity=190, limit_price=500.0),
        env,
        current_strategy_notional_usd=95_000.0,
        current_position_qty=190.0,
    )
    assert v_flatten.allowed is True
    assert v_flatten.violation_codes == []
    assert v_flatten.metrics["is_reducing"] is True
    assert v_flatten.metrics["projected_strategy_notional_usd"] == 0.0

    # 3. Covering a short position (current_position_qty=-190, BUY 190) MUST be allowed
    v_cover = evaluator.evaluate(
        _make_proposal(side=Side.BUY, quantity=190, limit_price=500.0),
        env,
        current_strategy_notional_usd=95_000.0,
        current_position_qty=-190.0,
    )
    assert v_cover.allowed is True
    assert v_cover.metrics["is_reducing"] is True
    assert v_cover.metrics["projected_strategy_notional_usd"] == 0.0

    # 4. Explicit is_reducing=True partial close is allowed and subtracts notional
    v_explicit = evaluator.evaluate(
        _make_proposal(side=Side.SELL, quantity=60, limit_price=500.0),
        env,
        current_strategy_notional_usd=95_000.0,
        is_reducing=True,
    )
    assert v_explicit.allowed is True
    assert v_explicit.metrics["is_reducing"] is True
    assert v_explicit.metrics["projected_strategy_notional_usd"] == 65_000.0

    # 5. Overselling past flat (long 100, SELL 150) is NOT risk-reducing and is blocked
    v_flip = evaluator.evaluate(
        _make_proposal(side=Side.SELL, quantity=150, limit_price=500.0),
        env,
        current_strategy_notional_usd=50_000.0,
        current_position_qty=100.0,
    )
    assert v_flip.allowed is False
    assert v_flip.metrics["is_reducing"] is False
    assert "ENVELOPE_NOTIONAL_EXCEEDED" in v_flip.violation_codes


def test_envelope_ed25519_sign_and_verify() -> None:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    env = _make_envelope()

    digest, sig = sign_envelope_ed25519(env, priv)
    assert digest == compute_envelope_signature_hash(env)
    assert len(digest) == 64
    assert sig.startswith("ed25519:")
    assert verify_envelope_ed25519(env, sig, pub) is True

    # Tampering with signed terms invalidates the Ed25519 signature
    tampered = env.model_copy(update={"max_order_notional_usd": 999_999.0})
    assert verify_envelope_ed25519(tampered, sig, pub) is False
    assert verify_envelope_ed25519(env, "ed25519:not_valid_base64!!!", pub) is False
    assert verify_envelope_ed25519(env, "sha256:" + digest, pub) is False


def test_envelope_evaluator_authority_public_key_pem_fail_closed() -> None:
    from cryptography.hazmat.primitives import serialization

    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    wrong_pub_pem = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    evaluator = EnvelopeEvaluator()
    proposal = _make_proposal(symbol="SPY", quantity=10, limit_price=500.0)

    # 1. Unsigned envelope (default sha256 digest only) fails closed when authority_public_key_pem is supplied
    unsigned_env = _make_envelope()
    v_unsigned = evaluator.evaluate(proposal, unsigned_env, authority_public_key_pem=pub_pem)
    assert v_unsigned.allowed is False
    assert "ENVELOPE_INVALID_SIGNATURE" in v_unsigned.violation_codes

    # 2. Validly signed Ed25519 envelope passes
    digest, sig = sign_envelope_ed25519(unsigned_env, priv)
    signed_env = unsigned_env.model_copy(
        update={
            "envelope_digest": digest,
            "signature_hash": sig,
            "signature_algorithm": "ed25519",
        }
    )
    v_valid = evaluator.evaluate(proposal, signed_env, authority_public_key_pem=pub_pem)
    assert v_valid.allowed is True
    assert v_valid.violation_codes == []

    # 3. Tampered signed envelope fails closed
    tampered_env = signed_env.model_copy(update={"max_order_notional_usd": 500_000.0})
    v_tampered = evaluator.evaluate(proposal, tampered_env, authority_public_key_pem=pub_pem)
    assert v_tampered.allowed is False
    assert "ENVELOPE_INVALID_SIGNATURE" in v_tampered.violation_codes

    # 4. Wrong authority public key fails closed
    v_wrong_key = evaluator.evaluate(proposal, signed_env, authority_public_key_pem=wrong_pub_pem)
    assert v_wrong_key.allowed is False
    assert "ENVELOPE_INVALID_SIGNATURE" in v_wrong_key.violation_codes


def test_envelope_contract_multiplier_and_flat_account_is_reducing_guard() -> None:
    evaluator = EnvelopeEvaluator()
    env = _make_envelope(
        allowed_symbols=["CL", "SPY"],
        max_order_notional_usd=25_000.0,
        max_strategy_notional_usd=100_000.0,
    )

    # 1. Futures contract multiplier: 1 CL @ $75 with 1000x multiplier = $75,000 > $25,000 cap
    cl_proposal = _make_proposal(symbol="CL", quantity=1, limit_price=75.0)
    v_cl_blocked = evaluator.evaluate(cl_proposal, env, contract_multiplier=1000.0)
    assert v_cl_blocked.allowed is False
    assert "ENVELOPE_NOTIONAL_EXCEEDED" in v_cl_blocked.violation_codes
    assert v_cl_blocked.metrics["order_notional_usd"] == pytest.approx(75_000.0)
    assert v_cl_blocked.metrics["contract_multiplier"] == 1000.0

    # Without multiplier (1.0), 1 @ $75 = $75 would pass
    v_cl_default = evaluator.evaluate(cl_proposal, env)
    assert v_cl_default.allowed is True
    assert v_cl_default.metrics["order_notional_usd"] == pytest.approx(75.0)

    # 2. Flat account cannot bypass notional cap by passing is_reducing=True
    oversized = _make_proposal(symbol="SPY", side=Side.SELL, quantity=100, limit_price=500.0)
    v_flat_bypass = evaluator.evaluate(
        oversized,
        env,
        current_position_qty=0.0,
        current_strategy_notional_usd=0.0,
        is_reducing=True,
    )
    assert v_flat_bypass.allowed is False
    assert v_flat_bypass.metrics["is_reducing"] is False
    assert "ENVELOPE_NOTIONAL_EXCEEDED" in v_flat_bypass.violation_codes

    # 3. With actual open position (or open strategy notional), is_reducing=True is honored
    v_open_close = evaluator.evaluate(
        oversized,
        env,
        current_position_qty=100.0,
        current_strategy_notional_usd=50_000.0,
        is_reducing=True,
    )
    assert v_open_close.allowed is True
    assert v_open_close.metrics["is_reducing"] is True
