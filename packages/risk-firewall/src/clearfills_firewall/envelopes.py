"""Signed Strategy Envelopes, Live Equity-Curve Decay Auto-Kill, and 3 Named Risk Profiles.

Enables systematic/quant strategies to run autonomously on CPU at $0 LLM token cost
and <1ms deterministic evaluation latency within a human-signed Strategy Envelope,
with runaway-loop throttling and live equity-curve decay / drawdown auto-kill.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional, Sequence
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import OrderType, TradeProposal, utc_now
from .policy import RiskPolicy, default_allocation_sleeves


class RiskProfilePreset(str, Enum):
    """Three named risk profiles matching distinct investing & systematic trading styles."""

    LONG_TERM_HOLDCO = "long_term_holdco"
    ACTIVE_SWING = "active_swing"
    SYSTEMATIC_QUANT = "systematic_quant"


def _normalize_profile(profile: str | RiskProfilePreset) -> RiskProfilePreset:
    if isinstance(profile, RiskProfilePreset):
        return profile
    normalized = str(profile).strip().lower()
    try:
        return RiskProfilePreset(normalized)
    except ValueError as exc:
        valid = ", ".join(p.value for p in RiskProfilePreset)
        raise ValueError(f"Unknown risk profile '{profile}'. Expected one of: {valid}") from exc


def policy_from_profile(profile: str | RiskProfilePreset) -> RiskPolicy:
    """Build a deterministic RiskPolicy from one of the 3 named ClearFills Risk Profiles.

    Profiles:
    - ``long_term_holdco``: Limit-only, no mandatory stop-loss, concentration & wash-sale focus.
    - ``active_swing``: Limit-only, mandatory stop-loss, 1.5% max risk/trade, 3.0% max daily loss.
    - ``systematic_quant``: Market orders allowed, no mandatory stop-loss, 150% max gross exposure.
    """
    preset = _normalize_profile(profile)

    if preset == RiskProfilePreset.LONG_TERM_HOLDCO:
        return RiskPolicy(
            policy_version="profile:long_term_holdco",
            allow_market_orders=False,
            require_stop_loss=False,
            allow_shorting=False,
            allow_margin=False,
            max_risk_per_trade_pct=5.0,
            max_total_heat_pct=25.0,
            max_daily_loss_pct=5.0,
            max_open_positions=25,
            max_order_notional_usd=250_000.0,
            max_gross_exposure_pct=100.0,
            enforce_kelly_sizing=False,
            sleeves=default_allocation_sleeves(),
        )

    if preset == RiskProfilePreset.ACTIVE_SWING:
        return RiskPolicy(
            policy_version="profile:active_swing",
            allow_market_orders=False,
            require_stop_loss=True,
            allow_shorting=False,
            allow_margin=False,
            max_risk_per_trade_pct=1.5,
            max_total_heat_pct=8.0,
            max_daily_loss_pct=3.0,
            max_open_positions=10,
            max_order_notional_usd=50_000.0,
            max_gross_exposure_pct=100.0,
            enforce_kelly_sizing=True,
        )

    # RiskProfilePreset.SYSTEMATIC_QUANT
    return RiskPolicy(
        policy_version="profile:systematic_quant",
        allow_market_orders=True,
        require_stop_loss=False,
        allow_shorting=True,
        allow_margin=True,
        max_risk_per_trade_pct=2.0,
        max_total_heat_pct=25.0,
        max_daily_loss_pct=3.0,
        max_open_positions=50,
        max_order_notional_usd=100_000.0,
        max_gross_exposure_pct=150.0,
        enforce_kelly_sizing=False,
    )


def list_risk_profiles() -> list[dict[str, Any]]:
    """Return all 3 named Risk Profiles with their exact parameter presets and descriptions."""
    profiles: list[dict[str, Any]] = [
        {
            "id": RiskProfilePreset.LONG_TERM_HOLDCO.value,
            "name": "Long-Term HoldCo",
            "summary": (
                "Fundamental & holdco investing without forced stop-losses. "
                "Enforces limit orders, 25% single-position concentration cap, and wash-sale / PFIC guards."
            ),
            "highlights": [
                "No mandatory stop-loss (avoids getting shaken out of long-term convictions)",
                "Limit orders only (protects against wide spreads & slippage)",
                "25% max single-position concentration & wash-sale / tax-compliance focus",
            ],
            "envelope_defaults": {
                "allow_market_orders": False,
                "require_stop_loss": False,
                "max_position_pct": 25.0,
                "max_orders_per_minute": 2,
                "max_gross_exposure_pct": 100.0,
            },
            "policy": policy_from_profile(RiskProfilePreset.LONG_TERM_HOLDCO).model_dump(mode="json"),
        },
        {
            "id": RiskProfilePreset.ACTIVE_SWING.value,
            "name": "Active Swing",
            "summary": (
                "Disciplined discretionary & AI-assisted swing trading with mandatory protective stops, "
                "1.5% max risk per trade, and a 3.0% daily loss circuit breaker."
            ),
            "highlights": [
                "Mandatory protective stop-loss on every entry",
                "Limit orders only; 1.5% max risk per trade",
                "3.0% daily loss circuit breaker & 8.0% total portfolio heat cap",
            ],
            "envelope_defaults": {
                "allow_market_orders": False,
                "require_stop_loss": True,
                "max_risk_per_trade_pct": 1.5,
                "max_daily_loss_pct": 3.0,
                "max_orders_per_minute": 5,
                "max_gross_exposure_pct": 100.0,
            },
            "policy": policy_from_profile(RiskProfilePreset.ACTIVE_SWING).model_dump(mode="json"),
        },
        {
            "id": RiskProfilePreset.SYSTEMATIC_QUANT.value,
            "name": "Systematic Quant",
            "summary": (
                "Autonomous CPU-run momentum, stat-arb, and systematic strategies. "
                "Allows market orders without per-order stops, bounded by 150% gross exposure, "
                "10 orders/min runaway-loop throttle, and optional equity-curve decay auto-kill."
            ),
            "highlights": [
                "Market orders permitted & no per-order stop-loss required",
                "150% max gross exposure (1.5x) with shorting & margin enabled",
                "10 orders/min runaway-loop throttle + optional 200-DMA equity-curve auto-kill",
            ],
            "envelope_defaults": {
                "allow_market_orders": True,
                "require_stop_loss": False,
                "max_gross_exposure_pct": 150.0,
                "max_orders_per_minute": 10,
                "decay_ma_window": 200,
            },
            "policy": policy_from_profile(RiskProfilePreset.SYSTEMATIC_QUANT).model_dump(mode="json"),
        },
    ]
    return profiles


def compute_envelope_signature_hash(envelope: "StrategyEnvelope") -> str:
    """Compute a deterministic canonical SHA-256 hash over a StrategyEnvelope's signed terms."""
    canonical_payload = {
        "envelope_id": envelope.envelope_id,
        "strategy_id": envelope.strategy_id,
        "name": envelope.name,
        "profile": envelope.profile.value,
        "allowed_symbols": sorted(envelope.allowed_symbols),
        "blocked_symbols": sorted(envelope.blocked_symbols),
        "max_order_notional_usd": envelope.max_order_notional_usd,
        "max_strategy_notional_usd": envelope.max_strategy_notional_usd,
        "max_daily_loss_usd": envelope.max_daily_loss_usd,
        "max_orders_per_minute": envelope.max_orders_per_minute,
        "allow_market_orders": envelope.allow_market_orders,
        "require_stop_loss": envelope.require_stop_loss,
        "decay_ma_window": envelope.decay_ma_window,
        "max_drawdown_pct": envelope.max_drawdown_pct,
        "signed_by": envelope.signed_by,
        "expires_at": envelope.expires_at,
    }
    raw = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def sign_envelope_ed25519(
    envelope: "StrategyEnvelope",
    private_key: Ed25519PrivateKey,
) -> tuple[str, str]:
    """Compute canonical SHA-256 digest and sign it with an Ed25519 private key.

    Returns ``(envelope_digest, "ed25519:<base64_signature>")``.
    """
    digest = compute_envelope_signature_hash(envelope)
    raw_sig = private_key.sign(digest.encode("utf-8"))
    sig_b64 = base64.b64encode(raw_sig).decode("ascii")
    return digest, f"ed25519:{sig_b64}"


def _load_ed25519_public_key(
    key: Ed25519PublicKey | bytes | str,
) -> Optional[Ed25519PublicKey]:
    if isinstance(key, Ed25519PublicKey):
        return key
    try:
        pem_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        loaded = serialization.load_pem_public_key(pem_bytes)
        return loaded if isinstance(loaded, Ed25519PublicKey) else None
    except Exception:
        return None


def verify_envelope_ed25519(
    envelope: "StrategyEnvelope",
    signature: str | bytes | Ed25519PublicKey,
    public_key: Optional[Ed25519PublicKey | bytes | str] = None,
) -> bool:
    """Verify an ``ed25519:<base64_signature>`` over a StrategyEnvelope's canonical SHA-256 digest.

    Supports both ``verify_envelope_ed25519(envelope, signature, public_key)`` and the
    shorthand ``verify_envelope_ed25519(envelope, authority_public_key_pem)`` which verifies
    ``envelope.signature_hash`` against the provided Ed25519 public key or PEM bytes.
    """
    if public_key is None:
        resolved_key = _load_ed25519_public_key(signature)
        sig_str = envelope.signature_hash
    else:
        resolved_key = _load_ed25519_public_key(public_key)
        sig_str = signature if isinstance(signature, str) else ""

    if resolved_key is None or not isinstance(sig_str, str) or not sig_str.startswith("ed25519:"):
        return False
    sig_b64 = sig_str[len("ed25519:") :]
    if not sig_b64:
        return False
    try:
        raw_sig = base64.b64decode(sig_b64.encode("ascii"), validate=True)
        digest = compute_envelope_signature_hash(envelope)
        resolved_key.verify(raw_sig, digest.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


class StrategyEnvelope(BaseModel):
    """Human-signed risk envelope allowing autonomous CPU strategies to execute within hard caps."""

    model_config = ConfigDict(extra="forbid")

    envelope_id: str = Field(default_factory=lambda: f"env_{uuid4().hex[:16]}")
    strategy_id: str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=128)
    profile: RiskProfilePreset = Field(default=RiskProfilePreset.SYSTEMATIC_QUANT)
    allowed_symbols: list[str] = Field(
        default_factory=list,
        description="Optional symbol allowlist (empty list = any symbol not in blocked_symbols).",
    )
    blocked_symbols: list[str] = Field(default_factory=list)
    max_order_notional_usd: float = Field(..., gt=0.0)
    max_strategy_notional_usd: float = Field(..., gt=0.0)
    max_daily_loss_usd: float = Field(..., gt=0.0)
    max_orders_per_minute: int = Field(
        default=10,
        ge=1,
        description="Runaway-loop throttle: maximum orders permitted in any rolling 60-second window.",
    )
    allow_market_orders: bool = Field(default=False)
    require_stop_loss: bool = Field(default=False)
    decay_ma_window: Optional[int] = Field(
        default=None,
        ge=2,
        description="Optional equity-curve moving-average window (e.g. 200 for 200-DMA auto-kill).",
    )
    max_drawdown_pct: Optional[float] = Field(
        default=None,
        gt=0.0,
        le=100.0,
        description="Optional peak-to-trough max drawdown threshold in percent (e.g. 10.0 for 10%).",
    )
    signed_by: str = Field(..., min_length=1, max_length=256)
    envelope_digest: str = Field(
        default="",
        description="Canonical SHA-256 hex digest over the envelope's signed terms.",
    )
    signature_hash: str = Field(default="")
    signature_algorithm: str = Field(
        default="sha256",
        description="Cryptographic algorithm used to produce signature_hash (e.g. 'ed25519', 'hmac-sha256', 'sha256').",
    )
    signing_key_id: Optional[str] = Field(
        default=None,
        description="Identifier of the server Ed25519 signing key when signature_algorithm='ed25519'.",
    )
    expires_at: Optional[str] = Field(
        default=None,
        description="Optional ISO-8601 UTC expiry timestamp.",
    )
    active: bool = Field(default=True)

    @field_validator("allowed_symbols", "blocked_symbols")
    @classmethod
    def _normalize_symbols(cls, v: list[str]) -> list[str]:
        return [s.strip().upper() for s in v if isinstance(s, str) and s.strip()]

    def model_post_init(self, __context: Any) -> None:
        digest = compute_envelope_signature_hash(self)
        if not self.envelope_digest:
            object.__setattr__(self, "envelope_digest", digest)
        if not self.signature_hash:
            object.__setattr__(self, "signature_hash", digest)


class EnvelopeVerdict(BaseModel):
    """Deterministic sub-millisecond verdict returned by EnvelopeEvaluator."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    auto_kill_triggered: bool = False
    auto_flatten_recommended: bool = False
    violation_codes: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)


def _parse_iso_utc(raw: str) -> Optional[datetime]:
    text = raw.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _coerce_timestamp_utc(value: datetime | float | int | str) -> Optional[datetime]:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        return _parse_iso_utc(value)
    return None


class EnvelopeEvaluator:
    """Zero-LLM-token, <1ms deterministic evaluator for signed Strategy Envelopes."""

    def evaluate(
        self,
        proposal: TradeProposal,
        envelope: StrategyEnvelope,
        recent_order_timestamps: Optional[Sequence[datetime | float | int | str]] = None,
        equity_curve: Optional[Sequence[float]] = None,
        *,
        current_strategy_notional_usd: float = 0.0,
        daily_pnl_usd: float = 0.0,
        now: Optional[datetime] = None,
        reference_price: Optional[float] = None,
        is_reducing: bool = False,
        current_position_qty: float = 0.0,
        authority_public_key_pem: Optional[bytes] = None,
        contract_multiplier: float = 1.0,
    ) -> EnvelopeVerdict:
        """Deterministically evaluate a TradeProposal against a signed StrategyEnvelope.

        Checks:
        - ENVELOPE_INVALID_SIGNATURE (when authority_public_key_pem is provided)
        - ENVELOPE_INACTIVE
        - ENVELOPE_EXPIRED
        - ENVELOPE_SYMBOL_NOT_ALLOWED
        - ENVELOPE_MARKET_ORDER_FORBIDDEN
        - ENVELOPE_STOP_LOSS_REQUIRED
        - ENVELOPE_NOTIONAL_EXCEEDED
        - ENVELOPE_ORDER_RATE_EXCEEDED (runaway-loop throttle)
        - ENVELOPE_DAILY_LOSS_BREACHED
        - ENVELOPE_EQUITY_CURVE_DECAY (triggers auto_kill_triggered + auto_flatten_recommended)
        - ENVELOPE_MAX_DRAWDOWN_BREACHED (triggers auto_kill_triggered + auto_flatten_recommended)
        """
        t0 = time.perf_counter()
        eval_now = now.astimezone(timezone.utc) if now is not None else utc_now()

        violation_codes: list[str] = []
        reasons: list[str] = []
        auto_kill_triggered = False
        auto_flatten_recommended = False
        metrics: dict[str, Any] = {
            "envelope_id": envelope.envelope_id,
            "strategy_id": envelope.strategy_id,
            "profile": envelope.profile.value,
        }

        def add_violation(code: str, message: str) -> None:
            if code not in violation_codes:
                violation_codes.append(code)
            reasons.append(message)

        # 0. Optional strict Ed25519 authority signature verification (fail-closed)
        if authority_public_key_pem is not None:
            if not verify_envelope_ed25519(envelope, authority_public_key_pem):
                add_violation(
                    "ENVELOPE_INVALID_SIGNATURE",
                    f"Strategy envelope '{envelope.envelope_id}' failed Ed25519 signature verification (invalid, tampered, or unsigned).",
                )

        # 1. Active status
        if not envelope.active:
            add_violation(
                "ENVELOPE_INACTIVE",
                f"Strategy envelope '{envelope.envelope_id}' is inactive or has been killed.",
            )

        # 2. Expiry check (fail-closed on unparseable expires_at)
        if envelope.expires_at is not None:
            parsed_expiry = _parse_iso_utc(envelope.expires_at)
            if parsed_expiry is None:
                add_violation(
                    "ENVELOPE_EXPIRED",
                    f"Strategy envelope '{envelope.envelope_id}' has an invalid expires_at timestamp '{envelope.expires_at}'.",
                )
            elif eval_now >= parsed_expiry:
                add_violation(
                    "ENVELOPE_EXPIRED",
                    f"Strategy envelope '{envelope.envelope_id}' expired at {parsed_expiry.isoformat()}.",
                )

        # 3. Symbol allowlist / blocklist
        sym = proposal.symbol.strip().upper()
        if sym in envelope.blocked_symbols:
            add_violation(
                "ENVELOPE_SYMBOL_NOT_ALLOWED",
                f"Symbol '{sym}' is explicitly blocked by envelope '{envelope.envelope_id}'.",
            )
        elif envelope.allowed_symbols and sym not in envelope.allowed_symbols:
            add_violation(
                "ENVELOPE_SYMBOL_NOT_ALLOWED",
                f"Symbol '{sym}' is not in envelope allowed_symbols {envelope.allowed_symbols}.",
            )

        # 4. Order type & stop-loss constraints
        if proposal.order_type != OrderType.LIMIT and not envelope.allow_market_orders:
            add_violation(
                "ENVELOPE_MARKET_ORDER_FORBIDDEN",
                f"Order type '{proposal.order_type.value}' is not permitted by envelope '{envelope.envelope_id}' (allow_market_orders=False).",
            )

        if envelope.require_stop_loss and proposal.stop_price is None:
            add_violation(
                "ENVELOPE_STOP_LOSS_REQUIRED",
                f"Envelope '{envelope.envelope_id}' requires a protective stop_price on all orders.",
            )

        # 5. Per-order and aggregate strategy notional caps
        # Risk-reducing closes/flattens must NEVER be blocked by notional caps,
        # but is_reducing=True is only honored when open position/notional exists.
        side_str = (
            proposal.side.value.upper()
            if hasattr(proposal.side, "value")
            else str(proposal.side).strip().upper()
        )
        qty = abs(float(proposal.quantity))
        has_open_exposure = (current_position_qty != 0.0) or (float(current_strategy_notional_usd) > 0.0)
        reducing = (
            (bool(is_reducing) and has_open_exposure)
            or (current_position_qty > 0 and side_str == "SELL" and qty <= current_position_qty)
            or (current_position_qty < 0 and side_str == "BUY" and qty <= abs(current_position_qty))
        )
        metrics["is_reducing"] = reducing

        multiplier = max(1.0, float(contract_multiplier))
        metrics["contract_multiplier"] = multiplier

        effective_price = proposal.limit_price if proposal.limit_price is not None else reference_price
        if effective_price is None or effective_price <= 0:
            if not reducing:
                add_violation(
                    "ENVELOPE_NOTIONAL_EXCEEDED",
                    "Missing positive limit_price or reference_price to verify order notional against envelope cap.",
                )
        else:
            order_notional = abs(qty * float(effective_price) * multiplier)
            current_notional = max(0.0, float(current_strategy_notional_usd))
            if reducing:
                projected_strategy_notional = max(0.0, current_notional - order_notional)
            else:
                projected_strategy_notional = current_notional + order_notional
            metrics["order_notional_usd"] = round(order_notional, 4)
            metrics["projected_strategy_notional_usd"] = round(projected_strategy_notional, 4)

            if not reducing:
                if order_notional > envelope.max_order_notional_usd:
                    add_violation(
                        "ENVELOPE_NOTIONAL_EXCEEDED",
                        f"Order notional ${order_notional:,.2f} exceeds max_order_notional_usd ${envelope.max_order_notional_usd:,.2f}.",
                    )
                if projected_strategy_notional > envelope.max_strategy_notional_usd:
                    add_violation(
                        "ENVELOPE_NOTIONAL_EXCEEDED",
                        f"Projected strategy notional ${projected_strategy_notional:,.2f} exceeds max_strategy_notional_usd ${envelope.max_strategy_notional_usd:,.2f}.",
                    )

        # 6. Runaway-loop throttle (orders per rolling 60s window)
        window_start = eval_now - timedelta(seconds=60)
        recent_count = 0
        if recent_order_timestamps:
            for ts_raw in recent_order_timestamps:
                ts = _coerce_timestamp_utc(ts_raw)
                if ts is not None and window_start < ts <= eval_now:
                    recent_count += 1
        metrics["orders_in_last_minute"] = recent_count
        metrics["max_orders_per_minute"] = envelope.max_orders_per_minute
        if recent_count >= envelope.max_orders_per_minute:
            add_violation(
                "ENVELOPE_ORDER_RATE_EXCEEDED",
                f"Runaway-loop throttle tripped: {recent_count} orders in last 60s >= max_orders_per_minute ({envelope.max_orders_per_minute}).",
            )

        # 7. Daily loss circuit breaker
        daily_loss_usd = abs(daily_pnl_usd) if daily_pnl_usd < 0 else 0.0
        metrics["daily_loss_usd"] = round(daily_loss_usd, 4)
        if daily_loss_usd >= envelope.max_daily_loss_usd:
            add_violation(
                "ENVELOPE_DAILY_LOSS_BREACHED",
                f"Strategy daily loss ${daily_loss_usd:,.2f} >= max_daily_loss_usd ${envelope.max_daily_loss_usd:,.2f}.",
            )

        # 8. Live equity-curve decay auto-kill (live equity < N-point SMA)
        clean_curve = [float(x) for x in equity_curve] if equity_curve else []
        if clean_curve:
            live_equity = clean_curve[-1]
            metrics["live_equity"] = round(live_equity, 4)

            if envelope.decay_ma_window is not None and len(clean_curve) >= envelope.decay_ma_window:
                window_slice = clean_curve[-envelope.decay_ma_window :]
                sma_val = sum(window_slice) / len(window_slice)
                metrics["decay_sma"] = round(sma_val, 4)
                metrics["decay_ma_window"] = envelope.decay_ma_window
                if live_equity < sma_val:
                    auto_kill_triggered = True
                    auto_flatten_recommended = True
                    add_violation(
                        "ENVELOPE_EQUITY_CURVE_DECAY",
                        f"Live strategy equity ({live_equity:,.2f}) dropped below its {envelope.decay_ma_window}-period moving average ({sma_val:,.2f}); auto-kill triggered and flatten recommended.",
                    )

            # 9. Peak-to-trough rolling drawdown auto-kill
            if envelope.max_drawdown_pct is not None and len(clean_curve) >= 2:
                peak_equity = max(clean_curve)
                metrics["peak_equity"] = round(peak_equity, 4)
                if peak_equity > 0:
                    drawdown_pct = ((peak_equity - live_equity) / peak_equity) * 100.0
                    metrics["drawdown_pct"] = round(drawdown_pct, 4)
                    if drawdown_pct >= envelope.max_drawdown_pct:
                        auto_kill_triggered = True
                        auto_flatten_recommended = True
                        add_violation(
                            "ENVELOPE_MAX_DRAWDOWN_BREACHED",
                            f"Strategy drawdown {drawdown_pct:.2f}% >= max_drawdown_pct {envelope.max_drawdown_pct:.2f}%; auto-kill triggered and flatten recommended.",
                        )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        metrics["eval_latency_ms"] = round(elapsed_ms, 4)

        return EnvelopeVerdict(
            allowed=len(violation_codes) == 0,
            auto_kill_triggered=auto_kill_triggered,
            auto_flatten_recommended=auto_flatten_recommended,
            violation_codes=violation_codes,
            reasons=reasons,
            metrics=metrics,
        )
