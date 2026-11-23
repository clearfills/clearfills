"""Pluggable upstream agent backend shims for open-source trading frameworks.

Allows frameworks such as `TauricResearch/TradingAgents` and `virattt/ai-hedge-fund`
to route proposals through the ClearFills Pre-Trade Risk Firewall without modifying
their core agent loops.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .models import OrderType, Side, TradeProposal, VenueType


def _parse_side(raw_action: str) -> Side:
    normalized = raw_action.strip().upper()
    if normalized in {"BUY", "LONG", "BULLISH", "COVER"} or re.search(r"\bBUY\b", normalized):
        return Side.BUY
    if normalized in {"SELL", "SHORT", "BEARISH"} or re.search(r"\bSELL\b|\bSHORT\b", normalized):
        return Side.SELL
    raise ValueError(f"Unsupported or non-actionable trade decision: '{raw_action}'")


def _normalize_confidence(raw: Any, default: float = 0.55) -> float:
    if raw is None:
        return default
    val = float(raw)
    if val > 1.0:
        # Frameworks like ai-hedge-fund often emit confidence on a 0..100 scale
        val = val / 100.0
    return max(0.0, min(1.0, val))


def _coerce_float(val: Any) -> Optional[float]:
    if val is None or val == "":
        return None
    return float(val)


def from_tradingagents_decision(payload: dict[str, Any]) -> TradeProposal:
    """Map a `TauricResearch/TradingAgents` state/decision dict into a `TradeProposal`.

    Expected fields (supports standard TradingAgents graph output):
    - `final_trade_decision`: str (e.g. `"BUY"`, `"FINAL TRANSACTION PROPOSAL: **BUY**"`) or dict
    - `company_of_interest` or `ticker` or `symbol`
    - `investment_debate_state`: optional dict with `bull_history`, `bear_history`, `judge_decision`
    - `risk_debate_state`: optional dict with `judge_decision`
    - `quantity`, `limit_price` (or `price`), `stop_price`, `target_price`, `venue`, `agent_id`
    """
    decision_raw = payload.get("final_trade_decision")
    if decision_raw is None:
        raise ValueError("TradingAgents payload missing 'final_trade_decision'")

    if isinstance(decision_raw, dict):
        action_str = str(decision_raw.get("action") or decision_raw.get("decision") or "")
        decision_rationale = str(decision_raw.get("reasoning") or decision_raw.get("summary") or "")
    else:
        action_str = str(decision_raw)
        decision_rationale = action_str

    side = _parse_side(action_str)

    symbol = str(
        payload.get("company_of_interest")
        or payload.get("ticker")
        or payload.get("symbol")
        or ""
    ).strip()
    if not symbol:
        raise ValueError("TradingAgents payload missing 'company_of_interest' / 'ticker' / 'symbol'")

    debate = payload.get("investment_debate_state") or {}
    risk_debate = payload.get("risk_debate_state") or {}

    trace_parts: list[str] = []
    if decision_rationale:
        trace_parts.append(f"Final Decision: {decision_rationale}")
    if isinstance(debate, dict):
        if debate.get("bull_history"):
            trace_parts.append(f"Bull Case: {debate['bull_history']}")
        if debate.get("bear_history"):
            trace_parts.append(f"Bear Case: {debate['bear_history']}")
        if debate.get("judge_decision"):
            trace_parts.append(f"Research Judge: {debate['judge_decision']}")
    if isinstance(risk_debate, dict) and risk_debate.get("judge_decision"):
        trace_parts.append(f"Risk Judge: {risk_debate['judge_decision']}")

    citations: list[str] = list(payload.get("source_citations") or [])
    for report_key in ("market_report", "sentiment_report", "news_report", "fundamentals_report"):
        if payload.get(report_key):
            citations.append(f"tradingagents:{report_key}")

    quantity = float(payload.get("quantity", 1.0))
    limit_price = _coerce_float(payload.get("limit_price") or payload.get("price"))
    stop_price = _coerce_float(payload.get("stop_price"))
    target_price = _coerce_float(payload.get("target_price"))
    confidence = _normalize_confidence(payload.get("confidence"), default=0.60)

    venue = str(payload.get("venue", "ibkr"))
    venue_type_raw = str(payload.get("venue_type", VenueType.EQUITY.value)).upper()
    venue_type = VenueType(venue_type_raw)

    order_type_raw = str(payload.get("order_type", OrderType.LIMIT.value)).upper()
    order_type = OrderType(order_type_raw)

    return TradeProposal(
        agent_id=str(payload.get("agent_id", "tradingagents-orchestrator")),
        venue=venue,
        venue_type=venue_type,
        symbol=symbol,
        side=side,
        order_type=order_type,
        quantity=quantity,
        limit_price=limit_price,
        stop_price=stop_price,
        target_price=target_price,
        reasoning_trace="\n\n".join(trace_parts),
        source_citations=citations,
        confidence=confidence,
        strategy_id=str(payload.get("strategy_id", "tradingagents_debate")),
    )


def from_ai_hedge_fund_signal(payload: dict[str, Any]) -> TradeProposal:
    """Map a `virattt/ai-hedge-fund` portfolio manager / analyst signal into a `TradeProposal`.

    Expected fields:
    - `ticker` or `symbol`
    - `action` or `signal` (e.g. `"buy"`, `"sell"`, `"short"`, `"bullish"`, `"bearish"`)
    - `quantity`
    - `confidence` (0..100 or 0.0..1.0)
    - `reasoning`: str or dict
    - `analyst_signals`: optional dict of `{analyst_name: {signal, confidence, reasoning}}`
    - `limit_price` (or `price`), `stop_price`, `target_price`, `venue`, `agent_id`
    """
    symbol = str(payload.get("ticker") or payload.get("symbol") or "").strip()
    if not symbol:
        raise ValueError("ai-hedge-fund payload missing 'ticker' / 'symbol'")

    raw_action = payload.get("action") or payload.get("signal")
    if not raw_action:
        raise ValueError("ai-hedge-fund payload missing 'action' / 'signal'")
    side = _parse_side(str(raw_action))

    quantity = float(payload.get("quantity", 1.0))
    confidence = _normalize_confidence(payload.get("confidence"), default=0.55)

    reasoning_raw = payload.get("reasoning", "")
    trace_parts: list[str] = []
    if isinstance(reasoning_raw, dict):
        for k, v in reasoning_raw.items():
            trace_parts.append(f"{k}: {v}")
    elif reasoning_raw:
        trace_parts.append(str(reasoning_raw))

    citations: list[str] = list(payload.get("source_citations") or [])
    analyst_signals = payload.get("analyst_signals") or {}
    if isinstance(analyst_signals, dict):
        for analyst_name, sig_data in analyst_signals.items():
            citations.append(f"ai-hedge-fund:{analyst_name}")
            if isinstance(sig_data, dict):
                sig_label = sig_data.get("signal", "neutral")
                sig_conf = sig_data.get("confidence", "")
                sig_reason = sig_data.get("reasoning", "")
                trace_parts.append(
                    f"[{analyst_name}] signal={sig_label} conf={sig_conf}: {sig_reason}"
                )

    limit_price = _coerce_float(payload.get("limit_price") or payload.get("price"))
    stop_price = _coerce_float(payload.get("stop_price"))
    target_price = _coerce_float(payload.get("target_price"))

    venue = str(payload.get("venue", "alpaca"))
    venue_type_raw = str(payload.get("venue_type", VenueType.EQUITY.value)).upper()
    venue_type = VenueType(venue_type_raw)

    order_type_raw = str(payload.get("order_type", OrderType.LIMIT.value)).upper()
    order_type = OrderType(order_type_raw)

    return TradeProposal(
        agent_id=str(payload.get("agent_id", "ai-hedge-fund-pm")),
        venue=venue,
        venue_type=venue_type,
        symbol=symbol,
        side=side,
        order_type=order_type,
        quantity=quantity,
        limit_price=limit_price,
        stop_price=stop_price,
        target_price=target_price,
        reasoning_trace="\n".join(trace_parts),
        source_citations=citations,
        confidence=confidence,
        strategy_id=str(payload.get("strategy_id", "ai_hedge_fund_consensus")),
    )
