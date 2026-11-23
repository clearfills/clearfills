"""Sanitized telemetry & Arena heartbeat publisher for ClearFills Desk OS."""

from __future__ import annotations

import re
from typing import Any, Literal

import httpx

_SENSITIVE_PATTERNS = [
    re.compile(r"\b(?:DU|U)\d{5,12}\b"),  # IBKR paper/live account IDs
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),  # IPv4 addresses
    re.compile(r"\b[a-zA-Z0-9-]+\.ts\.net\b"),  # Tailscale MagicDNS hostnames
    re.compile(r"\b(?:cf_sk_|sk_live_|whsec_|ghp_)[A-Za-z0-9_-]{8,}\b"),  # API/webhook tokens
]


def sanitize_text(text: str) -> str:
    """Strip account IDs, IP addresses, Tailscale hostnames, and secret tokens."""
    cleaned = text
    for pat in _SENSITIVE_PATTERNS:
        cleaned = pat.sub("[REDACTED]", cleaned)
    return cleaned


def publish_arena_heartbeat(
    *,
    api_base: str,
    ingest_token: str,
    desk_id: str,
    desk_name: str,
    stack_label: str,
    venue_tag: str,
    execution_mode: Literal["paper", "live"],
    net_return_pct: float,
    excess_vs_spy_pct: float,
    dsr: float,
    attestations_issued: int,
    vetoes_blocked: int,
    kill_switch_trips: int,
    latest_rationale: str,
) -> dict[str, Any]:
    """Publish a sanitized desk heartbeat to the ClearFills Arena API."""
    payload = {
        "id": desk_id,
        "name": desk_name,
        "stack_label": stack_label,
        "market": "EQUITIES_IBKR",
        "venue_tag": venue_tag,
        "execution_mode": execution_mode,
        "fill_source": "broker_live" if execution_mode == "live" else "broker_paper",
        "net_return_pct": net_return_pct,
        "excess_vs_spy_pct": excess_vs_spy_pct,
        "dsr": dsr,
        "attestations_issued": attestations_issued,
        "vetoes_blocked": vetoes_blocked,
        "kill_switch_trips": kill_switch_trips,
        "latest_rationale": sanitize_text(latest_rationale),
        "traces": [],
    }
    resp = httpx.post(
        f"{api_base.rstrip('/')}/api/v1/arena/ingest",
        json=payload,
        headers={"Authorization": f"Bearer {ingest_token}"},
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()
