"""Safe execution wrapper for TauricResearch/TradingAgents using clearfills-firewall.

Demonstrates how to gate TradingAgents debate output behind a deterministic
pre-trade risk firewall before any order reaches Interactive Brokers (IBKR)
or Alpaca:

1. Convert TradingAgents state dicts into a normalized `TradeProposal`.
2. Enforce limit orders, mandatory stop-losses, per-trade risk caps, and
   notional limits with zero LLM involvement in the approval decision.
3. Issue a single-use, 120-second Ed25519 `SignedAttestation` bound to the
   exact canonical order hash.
4. Verify and atomically consume the attestation at the execution boundary
   (`dispatch_check`) to block replay attacks and order tampering.

Run locally (zero broker credentials or network calls required):
    pip install clearfills-firewall
    python examples/tradingagents_safe_execution.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from clearfills_firewall import (
    FirewallService,
    PortfolioSnapshot,
    RiskPolicy,
    default_allocation_sleeves,
    from_tradingagents_decision,
)


def build_firewall(data_dir: Path) -> FirewallService:
    """Initialize a local deterministic risk firewall with 120s Ed25519 TTL."""
    policy = RiskPolicy(
        max_risk_per_trade_pct=1.0,
        max_open_positions=10,
        max_total_heat_pct=6.0,
        max_daily_loss_pct=2.0,
        require_stop_loss=True,
        max_order_notional_usd=25_000.0,
        allow_shorting=False,
        sleeves=default_allocation_sleeves(),
    )
    return FirewallService.from_data_dir(
        data_dir=data_dir,
        policy=policy,
        initialize_armed=True,
        ttl_seconds=120,
    )


def build_sample_portfolio() -> PortfolioSnapshot:
    """Generic paper portfolio snapshot ($100,000 NAV, $50,000 settled cash)."""
    return PortfolioSnapshot(
        account_id="DU1234567",
        nav_usd=100_000.0,
        cash_usd=50_000.0,
        daily_pnl_usd=0.0,
        session_entries=0,
        open_positions=[],
    )


def mock_tradingagents_output(
    *,
    symbol: str,
    order_type: str,
    quantity: float,
    limit_price: float | None,
    stop_price: float | None,
    target_price: float | None,
) -> dict[str, Any]:
    """Representative output dictionary from TauricResearch/TradingAgents."""
    return {
        "company_of_interest": symbol,
        "final_trade_decision": f"FINAL TRANSACTION PROPOSAL: **BUY** {symbol}",
        "investment_debate_state": {
            "bull_history": "Revenue growth accelerating with expanding gross margins.",
            "bear_history": "Valuation multiple leaves limited room for guidance misses.",
            "judge_decision": "Risk-reward favors a sized long entry with a defined stop.",
        },
        "risk_debate_state": {
            "judge_decision": "Approve only as a limit order with hard downside protection.",
        },
        "fundamentals_report": "10-Q cash flow and balance sheet summary.",
        "venue": "ibkr",
        "order_type": order_type,
        "quantity": quantity,
        "limit_price": limit_price,
        "stop_price": stop_price,
        "target_price": target_price,
        "confidence": 0.68,
        "agent_id": "tradingagents-orchestrator",
    }


def main() -> None:
    portfolio = build_sample_portfolio()

    with tempfile.TemporaryDirectory(prefix="clearfills_ta_") as tmp_dir:
        firewall = build_firewall(Path(tmp_dir))

        # 1. Unguarded output (missing stop-loss) -> deterministically VETOED
        raw_unsafe = mock_tradingagents_output(
            symbol="MSFT",
            order_type="LIMIT",
            quantity=25,
            limit_price=400.00,
            stop_price=None,
            target_price=440.00,
        )
        unsafe_proposal = from_tradingagents_decision(raw_unsafe)
        unsafe_decision = firewall.propose(unsafe_proposal, portfolio)
        print("[1] Unguarded TradingAgents proposal (no stop-loss)")
        print(f"    status={unsafe_decision.status.value} codes={unsafe_decision.reason_codes}")
        assert not unsafe_decision.approved

        # 2. Properly bounded limit order + hard stop -> APPROVED + Ed25519 attested
        raw_safe = mock_tradingagents_output(
            symbol="MSFT",
            order_type="LIMIT",
            quantity=25,
            limit_price=400.00,
            stop_price=380.00,
            target_price=440.00,
        )
        safe_proposal = from_tradingagents_decision(raw_safe)
        safe_decision = firewall.propose(safe_proposal, portfolio)
        print("\n[2] Bounded TradingAgents proposal (limit $400, stop $380, risk $500 / 0.5% NAV)")
        print(f"    status={safe_decision.status.value}")
        assert safe_decision.approved and safe_decision.attestation is not None

        attestation = safe_decision.attestation
        print(f"    attestation_id={attestation.attestation_id}")
        print(f"    expires_at={attestation.expires_at.isoformat()}")
        print(f"    order_hash={attestation.order_hash[:16]}...")

        # 3. Execution boundary check (single-use consumption before IBKR/Alpaca submit)
        dispatch_ok = firewall.dispatch_check(attestation=attestation, proposal=safe_proposal)
        print("\n[3] Execution boundary dispatch_check (first submission)")
        print(f"    allowed={dispatch_ok.allowed} reason={dispatch_ok.reason}")
        assert dispatch_ok.allowed

        # 4. Replay protection: reusing the same attestation is immediately blocked
        dispatch_replay = firewall.dispatch_check(attestation=attestation, proposal=safe_proposal)
        print("\n[4] Replay check (reusing the same attestation)")
        print(f"    allowed={dispatch_replay.allowed} reason={dispatch_replay.reason}")
        assert not dispatch_replay.allowed

        # 5. Verify SHA-256 hash-chained audit ledger
        audit = firewall.verify_audit()
        print("\n[5] Audit ledger verification")
        print(f"    valid={audit.valid} entries={audit.entry_count}")
        assert audit.valid


if __name__ == "__main__":
    main()
