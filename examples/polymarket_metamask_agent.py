"""Polymarket CLOB AI agent example with MetaMask EIP-712 hardware sign-off.

Shows how an AI agent proposes a Polymarket CLOB limit order with a 77-digit
uint256 `token_id`, applies fractional Kelly sizing and ClearFills notional cap
checks, queues the order to the ClearFills Approval Inbox (`venue="polymarket"`),
and lets the human sign the Polygon EIP-712 `CTFExchange` order directly in
MetaMask with zero private keys on disk or server.

Run standalone (zero API keys or wallet private keys required):
    python examples/polymarket_metamask_agent.py --dry-run

Queue into ClearFills Cloud Approval Inbox:
    export CLEARFILLS_API_KEY="cf_sk_..."
    python examples/polymarket_metamask_agent.py
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
    OrderType,
    PortfolioSnapshot,
    RiskPolicy,
    Side,
    TradeProposal,
)

CLOUD_API_URL = os.environ.get("CLEARFILLS_API_URL", "https://clearfills-api.fly.dev").rstrip("/")
POLYGON_CHAIN_ID = 137
POLYMARKET_CTF_EXCHANGE = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
SAMPLE_TOKEN_ID = "21742633143463906290569050155826241533067272736897614950488156847949938836455"


def fractional_kelly_shares(
    *,
    bankroll_usd: float,
    model_prob: float,
    market_price: float,
    kelly_fraction: float = 0.25,
    max_notional_usd: float = 1_000.0,
) -> tuple[float, float]:
    """Compute bounded fractional Kelly stake (USD) and share quantity for a binary YES contract."""
    if not (0.01 <= market_price <= 0.99) or model_prob <= market_price:
        return 0.0, 0.0
    full_kelly = (model_prob - market_price) / (1.0 - market_price)
    stake_usd = min(bankroll_usd * max(0.0, full_kelly) * kelly_fraction, max_notional_usd)
    shares = round(stake_usd / market_price, 2)
    return round(shares * market_price, 2), shares


def build_eip712_preview(token_id: str, limit_price: float, shares: float) -> dict[str, Any]:
    """Non-custodial Polygon EIP-712 payload signed by the human in MetaMask."""
    maker_amount = int(round(shares * limit_price * 1_000_000))  # 6-decimal USDC
    taker_amount = int(round(shares * 1_000_000))                # 6-decimal conditional tokens
    return {
        "domain": {
            "name": "Polymarket CTF Exchange",
            "version": "1",
            "chainId": POLYGON_CHAIN_ID,
            "verifyingContract": POLYMARKET_CTF_EXCHANGE,
        },
        "primaryType": "Order",
        "message": {
            "tokenId": token_id,
            "makerAmount": str(maker_amount),
            "takerAmount": str(taker_amount),
            "side": 0,  # BUY
            "signatureType": 0,  # EOA (MetaMask)
        },
    }


def queue_polymarket_approval(payload: dict[str, Any], *, api_key: str, dry_run: bool) -> dict[str, Any]:
    """Queue Polymarket order into ClearFills Inbox for MetaMask EIP-712 sign-off."""
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
    assert len(SAMPLE_TOKEN_ID) == 77 and SAMPLE_TOKEN_ID.isdigit()
    market_price, model_prob, bankroll_usd = 0.42, 0.54, 10_000.0
    notional_usd, shares = fractional_kelly_shares(
        bankroll_usd=bankroll_usd, model_prob=model_prob, market_price=market_price, kelly_fraction=0.20, max_notional_usd=500.0
    )

    policy = RiskPolicy(
        max_risk_per_trade_pct=5.0,
        max_open_positions=10,
        max_total_heat_pct=20.0,
        max_daily_loss_pct=5.0,
        require_stop_loss=False,  # Binary prediction markets have bounded $0 floor
        max_order_notional_usd=500.0,
    )
    portfolio = PortfolioSnapshot(
        account_id="POLY-METAMASK", nav_usd=bankroll_usd, cash_usd=bankroll_usd, daily_pnl_usd=0.0, session_entries=0, open_positions=[]
    )
    proposal = TradeProposal(
        symbol="FED-CUT-YES",
        side=Side.BUY,
        quantity=shares,
        order_type=OrderType.LIMIT,
        limit_price=market_price,
        venue="polymarket",
        agent_id="polymarket-research-agent",
        reasoning_trace=f"Model p={model_prob:.2f} vs CLOB ask={market_price:.2f}; 0.20x Kelly stake=${notional_usd:.2f}.",
    )

    with tempfile.TemporaryDirectory(prefix="clearfills_poly_") as tmp_dir:
        firewall = FirewallService.from_data_dir(data_dir=Path(tmp_dir), policy=policy, initialize_armed=True, ttl_seconds=120)
        decision = firewall.propose(proposal, portfolio)
        print(f"Polymarket | token_id={SAMPLE_TOKEN_ID[:12]}...({len(SAMPLE_TOKEN_ID)} digits) | {decision.status.value} | codes={decision.reason_codes}")
        assert decision.approved and decision.attestation is not None

        inbox_payload = {
            "symbol": proposal.symbol,
            "side": proposal.side.value,
            "quantity": proposal.quantity,
            "order_type": proposal.order_type.value,
            "limit_price": proposal.limit_price,
            "notional_usd": notional_usd,
            "attestation_id": decision.attestation.attestation_id,
            "proposal_id": proposal.proposal_id,
            "agent_id": proposal.agent_id,
            "venue": "polymarket",
            "token_id": SAMPLE_TOKEN_ID,
            "neg_risk": False,
            "reasoning_trace": proposal.reasoning_trace,
        }
        api_key = os.environ.get("CLEARFILLS_API_KEY", "").strip()
        queued = queue_polymarket_approval(inbox_payload, api_key=api_key, dry_run=dry_run)
        eip712 = build_eip712_preview(SAMPLE_TOKEN_ID, market_price, shares)
        print(f"Queued: {queued.get('status', queued.get('id'))} | MetaMask EIP-712 contract={eip712['domain']['verifyingContract']}")
        print("Zero private keys stored on disk or server; human signs directly in MetaMask.")
        assert firewall.verify_audit().valid


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Polymarket CLOB agent with ClearFills firewall + MetaMask EIP-712 sign-off.")
    parser.add_argument("--dry-run", action="store_true", help="Run locally without sending to ClearFills Cloud.")
    args = parser.parse_args()
    run(dry_run=args.dry_run or not os.environ.get("CLEARFILLS_API_KEY", "").strip())
