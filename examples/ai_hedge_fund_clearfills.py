"""Drop-in ClearFills wrapper for virattt/ai-hedge-fund.

Routes multi-analyst portfolio manager signals from `virattt/ai-hedge-fund`
through ClearFills' deterministic risk firewall, a multi-entity tax/compliance
guard check (Personal TFSA vs. Corporate HoldCo), and the 1-Tap Approval Inbox.

Run standalone (zero API keys required):
    python examples/ai_hedge_fund_clearfills.py --dry-run

Queue into ClearFills Cloud 1-Tap Approval Inbox:
    export CLEARFILLS_API_KEY="cf_sk_..."
    python examples/ai_hedge_fund_clearfills.py
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from clearfills_firewall import (
    FirewallService,
    PortfolioSnapshot,
    RiskDecision,
    RiskPolicy,
    TradeProposal,
    default_allocation_sleeves,
    from_ai_hedge_fund_signal,
)

CLOUD_API_URL = os.environ.get("CLEARFILLS_API_URL", "https://clearfills-api.fly.dev").rstrip("/")
US_DIVIDEND_ETFS = frozenset({"VTI", "VOO", "SPY", "SCHD", "SGOV", "QQQ"})
CANADIAN_PFIC_ETFS = frozenset({"VEQT", "XEQT", "VFV", "XUS", "ZSP", "CASH"})


def evaluate_multi_entity_guard(symbol: str, entity: str, *, us_person: bool = False) -> tuple[bool, str]:
    """Deterministic multi-entity guard (mirrors ClearFills Cloud v2 guards)."""
    sym = symbol.upper()
    if entity == "tfsa" and sym in US_DIVIDEND_ETFS:
        return False, "TREATY_WITHHOLDING_GUARD: 15% US dividend withholding applies in TFSA; route to RRSP or HoldCo."
    if us_person and sym in CANADIAN_PFIC_ETFS:
        return False, "PFIC_ESTATE_GUARD: Canadian-domiciled ETF triggers IRS Form 8621 PFIC reporting."
    return True, "PASS"


def queue_to_approval_inbox(
    proposal: TradeProposal,
    decision: RiskDecision,
    *,
    entity: str,
    api_key: str,
    dry_run: bool,
) -> dict[str, Any]:
    """Queue a firewall-attested, entity-cleared order for 1-tap Touch ID sign-off."""
    assert decision.approved and decision.attestation is not None
    payload = {
        "symbol": proposal.symbol,
        "side": proposal.side.value,
        "quantity": proposal.quantity,
        "order_type": proposal.order_type.value,
        "limit_price": proposal.limit_price,
        "stop_price": proposal.stop_price,
        "target_price": proposal.target_price,
        "notional_usd": round((proposal.limit_price or 0.0) * proposal.quantity, 2),
        "attestation_id": decision.attestation.attestation_id,
        "proposal_id": proposal.proposal_id,
        "agent_id": proposal.agent_id,
        "venue": proposal.venue,
        "entity": entity,
        "sleeve": decision.metrics.get("sleeve", "active_trading"),
        "reasoning_trace": proposal.reasoning_trace,
    }
    if dry_run or not api_key:
        return {"status": "dry_run_queued", "endpoint": f"{CLOUD_API_URL}/api/v1/cloud/approvals", "payload": payload}

    req = urllib.request.Request(
        url=f"{CLOUD_API_URL}/api/v1/cloud/approvals",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run(dry_run: bool) -> None:
    policy = RiskPolicy(
        max_risk_per_trade_pct=1.0,
        max_open_positions=10,
        max_total_heat_pct=8.0,
        max_daily_loss_pct=2.0,
        require_stop_loss=True,
        max_order_notional_usd=50_000.0,
        sleeves=default_allocation_sleeves(),
    )
    portfolio = PortfolioSnapshot(
        account_id="DU1234567", nav_usd=100_000.0, cash_usd=50_000.0, daily_pnl_usd=0.0, session_entries=0, open_positions=[]
    )

    pm_decisions: list[tuple[str, dict[str, Any]]] = [
        ("tfsa", {"ticker": "SCHD", "action": "buy", "quantity": 100, "confidence": 80, "limit_price": 80.0, "stop_price": 75.0, "venue": "ibkr", "reasoning": "Dividend growth allocation."}),
        ("holdco", {"ticker": "AAPL", "action": "buy", "quantity": 50, "confidence": 76, "limit_price": 200.0, "stop_price": 190.0, "target_price": 225.0, "venue": "alpaca", "reasoning": "Free cash flow durability."}),
        ("holdco", {"ticker": "SGOV", "action": "buy", "quantity": 200, "confidence": 95, "limit_price": 100.50, "stop_price": None, "venue": "ibkr", "reasoning": "Sweep idle corporate cash into T-bills."}),
    ]

    api_key = os.environ.get("CLEARFILLS_API_KEY", "").strip()
    with tempfile.TemporaryDirectory(prefix="clearfills_ahf_") as tmp_dir:
        firewall = FirewallService.from_data_dir(data_dir=Path(tmp_dir), policy=policy, initialize_armed=True, ttl_seconds=120)
        for entity, raw in pm_decisions:
            guard_ok, guard_msg = evaluate_multi_entity_guard(raw["ticker"], entity)
            if not guard_ok:
                print(f"{raw['ticker']:5s} | entity={entity:6s} | VETOED   | {guard_msg}")
                continue
            proposal = from_ai_hedge_fund_signal(raw)
            decision = firewall.propose(proposal, portfolio)
            print(f"{proposal.symbol:5s} | entity={entity:6s} | {decision.status.value:8s} | codes={decision.reason_codes}")
            if decision.approved and decision.attestation is not None:
                queued = queue_to_approval_inbox(proposal, decision, entity=entity, api_key=api_key, dry_run=dry_run)
                print(f"      -> Ed25519 attested ({decision.attestation.attestation_id}), inbox={queued.get('status', queued.get('id'))}")
        assert firewall.verify_audit().valid


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Route ai-hedge-fund output through ClearFills firewall + entity guards.")
    parser.add_argument("--dry-run", action="store_true", help="Preview firewall attestation and inbox payload locally.")
    args = parser.parse_args()
    run(dry_run=args.dry_run or not os.environ.get("CLEARFILLS_API_KEY", "").strip())
