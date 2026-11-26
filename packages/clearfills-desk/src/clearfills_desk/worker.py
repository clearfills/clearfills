"""Approval worker bridging ClearFills Cloud 1-Tap approvals to live/paper IBKR execution.

Security hardening guarantees:
- Single canonical WebAuthn verifier (`webauthn_verifier.py`) with pinned SPKI keys,
  strict `rpIdHash`, `origin`, `webauthn.get`, `UP` + `UV` flags, and mandatory
  nonce-bound challenge (`sha256(nonce:order_hash)`).
- Fail-closed live mode: when `allow_live=True` or account is non-`DU*`, WebAuthn
  co-signature defaults to `True` and refuses execution without a pinned passkey
  (`LIVE_PASSKEY_PIN_REQUIRED`).
- Per-poll mark-to-market drawdown monitor that automatically latches `killswitch.json`
  with `reason="DAILY_DRAWDOWN_BREACHED"` when `daily_loss_pct >= max_daily_loss_pct`.
- Split-key Ed25519 policy ticket verification (`authority_public_key_pem`, verify-only).
- Honest fill receipts: never fabricates `fill_price = fresh_price` on `"submitted"`.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional, TextIO

from clearfills_firewall import KillSwitch, OrderType, Side, SignedAttestation, TradeProposal

from .ibkr import IBKRExecutionAdapter, LiveExecutionSafetyError, mask_account_id
from .telemetry import sanitize_text
from .webauthn_verifier import (
    DEFAULT_WEBAUTHN_ORIGIN,
    DEFAULT_WEBAUTHN_RP_ID,
    canonical_order_digest,
    compute_approval_hash,
    extract_client_challenge,
    extract_webauthn_assertion,
    verify_webauthn_assertion,
)

DEFAULT_CLOUD_API_URL = "https://clearfills-api.fly.dev"
_IBKR_VENUE = "ibkr"
_DEFAULT_HEARTBEAT_INTERVAL_SEC = 15.0


class CloudHTTPError(RuntimeError):
    """Raised when ClearFills Cloud returns a non-2xx HTTP response."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = int(status_code)
        self.detail = detail
        super().__init__(f"HTTP {self.status_code}: {detail}" if detail else f"HTTP {self.status_code}")


def _is_claim_conflict(exc: Exception) -> bool:
    """Return True if an exception represents an HTTP 409 claim conflict."""
    if isinstance(exc, CloudHTTPError) and exc.status_code == 409:
        return True
    if isinstance(exc, urllib.error.HTTPError) and exc.code == 409:
        return True
    code = getattr(exc, "status_code", getattr(exc, "code", None))
    if code == 409:
        return True
    msg = str(exc).lower()
    return "409" in msg or "already claimed" in msg or "conflict" in msg


def _opt_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        num = float(value)
        return num if num == num else None
    except (TypeError, ValueError):
        return None


def _extract_approvals(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        raw = payload.get("approvals")
        if raw is None:
            raw = payload.get("items")
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
    return []


def _nested_order_fields(record: dict[str, Any]) -> dict[str, Any]:
    if isinstance(record.get("order_summary"), dict):
        return record["order_summary"]
    if isinstance(record.get("proposal"), dict):
        return record["proposal"]
    return {}


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Backwards-compatible aliases delegating to the single canonical verifier
# ---------------------------------------------------------------------------


def verify_operator_passkey_cosignature(
    record: dict[str, Any],
    trusted_spki_keys_b64: list[str],
    *,
    expected_rp_id: str = DEFAULT_WEBAUTHN_RP_ID,
    expected_origin: str = DEFAULT_WEBAUTHN_ORIGIN,
    trusted_credential_ids: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """Delegate to the single canonical fail-closed WebAuthn verifier."""
    return verify_webauthn_assertion(
        record,
        trusted_spki_keys_b64,
        expected_rp_id=expected_rp_id,
        expected_origin=expected_origin,
        trusted_credential_ids=trusted_credential_ids,
    )


def verify_local_webauthn_cosign(
    record: dict[str, Any],
    trusted_spki_b64: list[str],
    *,
    expected_rp_id: str = DEFAULT_WEBAUTHN_RP_ID,
    expected_origin: str = DEFAULT_WEBAUTHN_ORIGIN,
    trusted_credential_ids: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """Delegate to the single canonical fail-closed WebAuthn verifier."""
    return verify_webauthn_assertion(
        record,
        trusted_spki_b64,
        expected_rp_id=expected_rp_id,
        expected_origin=expected_origin,
        trusted_credential_ids=trusted_credential_ids,
    )


def verify_webauthn_cosignature(
    approval: dict[str, Any],
    registered_pubkeys_b64: list[str] | None = None,
    *,
    require_uv: bool = True,
    expected_rp_id: str = DEFAULT_WEBAUTHN_RP_ID,
    expected_origin: str = DEFAULT_WEBAUTHN_ORIGIN,
    trusted_credential_ids: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """Delegate to the single canonical fail-closed WebAuthn verifier.

    Note: `UV` (User Verified) and locally pinned keys are ALWAYS strictly required.
    """
    _ = require_uv  # UV is unconditionally enforced by verify_webauthn_assertion.
    return verify_webauthn_assertion(
        approval,
        list(registered_pubkeys_b64 or []),
        expected_rp_id=expected_rp_id,
        expected_origin=expected_origin,
        trusted_credential_ids=trusted_credential_ids,
    )


class ApprovalWorker:
    """Polls ClearFills Cloud for approved IBKR orders and executes them with strict fail-closed guards."""

    def __init__(
        self,
        adapter: IBKRExecutionAdapter,
        api_key: str,
        api_url: str = DEFAULT_CLOUD_API_URL,
        max_slippage_bps: float = 50.0,
        dry_run: bool = False,
        cloud_transport: Optional[Callable[[str, str, Optional[dict[str, Any]]], Any]] = None,
        timeout: float = 10.0,
        worker_id: Optional[str] = None,
        heartbeat_interval_sec: float = _DEFAULT_HEARTBEAT_INTERVAL_SEC,
        max_favorable_gap_bps: float = 1000.0,
        trusted_passkey_spki_b64: Optional[list[str]] = None,
        trusted_credential_ids: Optional[list[str]] = None,
        webauthn_rp_id: Optional[str] = None,
        webauthn_origin: Optional[str] = None,
        require_webauthn_cosign: Optional[bool] = None,
        require_passkey_cosign: Optional[bool] = None,
        require_passkey_uv: bool = True,
        authority_public_key_pem: Optional[str] = None,
    ) -> None:
        self.adapter = adapter
        self.api_key = api_key.strip()
        self.api_url = (api_url or DEFAULT_CLOUD_API_URL).strip().rstrip("/")
        self.max_slippage_bps = float(max_slippage_bps)
        self.max_favorable_gap_bps = float(max_favorable_gap_bps)
        self.dry_run = bool(dry_run)
        self._cloud_transport = cloud_transport
        self._timeout = float(timeout)
        desk_cfg = getattr(getattr(adapter, "runtime", None), "config", None)
        desk_id = getattr(desk_cfg, "desk_id", "desk")
        default_worker_id = f"{desk_id}-{socket.gethostname()}"
        self.worker_id = (worker_id or default_worker_id).strip() or default_worker_id
        self._heartbeat_interval_sec = float(heartbeat_interval_sec)
        self._last_heartbeat_at: Optional[float] = None
        self._used_passkey_challenges: set[str] = set()

        self._trusted_passkey_spki_b64: list[str] = [
            k.strip() for k in (trusted_passkey_spki_b64 or []) if isinstance(k, str) and k.strip()
        ]
        cfg_cred_ids = list(getattr(desk_cfg, "trusted_credential_ids", []) or [])
        self._trusted_credential_ids: list[str] = list(
            dict.fromkeys(
                c.strip()
                for c in [*cfg_cred_ids, *(trusted_credential_ids or [])]
                if isinstance(c, str) and c.strip()
            )
        )
        self._webauthn_rp_id: str = (
            (webauthn_rp_id or getattr(desk_cfg, "webauthn_rp_id", None) or DEFAULT_WEBAUTHN_RP_ID).strip()
        )
        self._webauthn_origin: str = (
            (webauthn_origin or getattr(desk_cfg, "webauthn_origin", None) or DEFAULT_WEBAUTHN_ORIGIN).strip()
        )

        # Fail-closed live mode detection: allow_live=True or non-DU account defaults cosign to True.
        ibkr_cfg = getattr(desk_cfg, "ibkr", None)
        account_id = str(getattr(ibkr_cfg, "account_id", "") or "").strip()
        allow_live = bool(getattr(ibkr_cfg, "allow_live", False))
        exec_mode = str(getattr(adapter, "execution_mode", getattr(adapter, "_mode", "paper")) or "paper").lower()
        self._is_live_mode: bool = (
            exec_mode == "live"
            or allow_live
            or (bool(account_id) and not account_id.startswith("DU"))
        )

        if require_webauthn_cosign is not None:
            self.require_webauthn_cosign: bool = bool(require_webauthn_cosign)
        else:
            self.require_webauthn_cosign = self._is_live_mode

        if require_passkey_cosign is not None:
            self.require_passkey_cosign: bool = bool(require_passkey_cosign)
        else:
            self.require_passkey_cosign = (
                self._is_live_mode
                or _env_flag("CLEARFILLS_REQUIRE_PASSKEY_COSIGN")
                or bool(getattr(desk_cfg, "require_passkey_cosign", False))
            )

        # UV is unconditionally enforced by verify_webauthn_assertion.
        self.require_passkey_uv: bool = True if require_passkey_uv else True

        # Split-key verify-only Ed25519 authority public key (no private key in worker).
        resolved_authority_pem = (
            authority_public_key_pem
            or getattr(desk_cfg, "authority_public_key_pem", None)
            or os.getenv("CLEARFILLS_AUTHORITY_PUBLIC_KEY_PEM")
            or ""
        ).strip()
        if resolved_authority_pem:
            self.adapter.runtime.set_authority_public_key(resolved_authority_pem)

    def _cloud_request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
    ) -> Any:
        if self._cloud_transport is not None:
            return self._cloud_transport(method, path, body)
        if not self.api_key:
            raise RuntimeError("CLEARFILLS_API_KEY is not configured")
        url = f"{self.api_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        data = json.dumps(body, default=str).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise CloudHTTPError(exc.code, detail) from exc

    def _report_execution(self, approval_id: str, payload: dict[str, Any]) -> None:
        if self.dry_run:
            return
        quoted_id = urllib.parse.quote(approval_id, safe="")
        try:
            self._cloud_request("POST", f"/api/v1/cloud/approvals/{quoted_id}/executed", payload)
        except Exception:
            # Best-effort reporting; never crash the worker loop on secondary callback errors.
            pass

    def _resolve_reference_price(self, side: str, quote: dict[str, Any]) -> Optional[float]:
        primary_key = "ask" if side == "BUY" else "bid"
        primary = _opt_float(quote.get(primary_key))
        if primary is not None and primary > 0:
            return primary
        last = _opt_float(quote.get("last"))
        if last is not None and last > 0:
            return last
        return None

    def _get_latchable_kill_switch(self) -> KillSwitch:
        fw_ks = getattr(self.adapter.runtime.firewall, "kill_switch", None)
        if isinstance(fw_ks, KillSwitch):
            return fw_ks
        return KillSwitch(self.adapter.runtime.state_dir / "firewall" / "killswitch.json")

    def _is_kill_switch_tripped(self) -> bool:
        fw_ks = getattr(self.adapter.runtime.firewall, "kill_switch", None)
        if fw_ks is not None:
            try:
                if fw_ks.status().tripped:
                    return True
            except Exception:
                return True
        local_ks_path = self.adapter.runtime.state_dir / "firewall" / "killswitch.json"
        if local_ks_path.exists():
            if KillSwitch(local_ks_path).is_tripped():
                return True
        return False

    def check_drawdown_and_latch_killswitch(self) -> Optional[dict[str, Any]]:
        """Monitor live mark-to-market drawdown on every poll cycle and auto-latch killswitch.json."""
        portfolio = self.adapter.build_portfolio_snapshot()
        max_daily_loss_pct = float(self.adapter.runtime.config.risk.max_daily_loss_pct)
        if portfolio.daily_loss_pct >= max_daily_loss_pct:
            ks = self._get_latchable_kill_switch()
            if not ks.is_tripped():
                ks.trip(reason="DAILY_DRAWDOWN_BREACHED", actor=self.worker_id)
            return {
                "tripped": True,
                "reason": "DAILY_DRAWDOWN_BREACHED",
                "daily_pnl_usd": portfolio.daily_pnl_usd,
                "daily_loss_pct": round(portfolio.daily_loss_pct, 4),
                "max_daily_loss_pct": max_daily_loss_pct,
            }
        return None

    def _process_approval(self, record: dict[str, Any]) -> dict[str, Any]:
        approval_id = str(record.get("approval_id") or record.get("id") or "").strip()
        nested = _nested_order_fields(record)
        symbol = str(record.get("symbol") or nested.get("symbol") or "").strip().upper()
        side = str(record.get("side") or nested.get("side") or "").strip().upper()
        quantity = _opt_float(
            record.get("quantity") if record.get("quantity") is not None else nested.get("quantity")
        )
        limit_price = _opt_float(
            record.get("limit_price")
            if record.get("limit_price") is not None
            else nested.get("limit_price")
        )
        stop_price = _opt_float(
            record.get("stop_price") if record.get("stop_price") is not None else nested.get("stop_price")
        )
        target_price = _opt_float(
            record.get("target_price")
            if record.get("target_price") is not None
            else nested.get("target_price")
        )
        order_type_raw = str(
            record.get("order_type") or nested.get("order_type") or OrderType.LIMIT.value
        ).strip().upper()
        agent_id = str(record.get("agent_id") or nested.get("agent_id") or "approval-worker").strip()
        reasoning_trace = str(
            record.get("reasoning_trace") or f"1-tap approved execution for {approval_id}"
        )

        # 3a. Atomically claim the approval (skipped in dry-run to avoid mutating cloud state).
        if not self.dry_run:
            quoted_id = urllib.parse.quote(approval_id, safe="")
            try:
                claim_resp = self._cloud_request("POST", f"/api/v1/cloud/approvals/{quoted_id}/claim", {})
                if isinstance(claim_resp, dict) and (
                    claim_resp.get("status_code") == 409 or claim_resp.get("claimed") is False
                ):
                    return {
                        "approval_id": approval_id,
                        "symbol": symbol,
                        "status": "claim_conflict",
                        "detail": "Approval already claimed by another worker.",
                    }
            except Exception as exc:
                if _is_claim_conflict(exc):
                    return {
                        "approval_id": approval_id,
                        "symbol": symbol,
                        "status": "claim_conflict",
                        "detail": sanitize_text(str(exc)),
                    }
                raise

        if not symbol or side not in {"BUY", "SELL"} or quantity is None or quantity <= 0 or limit_price is None or limit_price <= 0:
            detail = (
                f"Invalid approved order parameters for {approval_id}: "
                f"symbol={symbol!r}, side={side!r}, quantity={quantity!r}, limit_price={limit_price!r}"
            )
            self._report_execution(approval_id, {"status": "execution_failed", "detail": detail})
            return {
                "approval_id": approval_id,
                "symbol": symbol,
                "status": "execution_failed",
                "detail": detail,
            }

        # 3a-ii. Single canonical WebAuthn co-signature verification (fail-closed before IBKR).
        trusted_keys = list(getattr(self.adapter.runtime.config, "operator_passkey_spki_b64", []) or [])
        combined_pinned_keys: list[str] = list(dict.fromkeys([*trusted_keys, *self._trusted_passkey_spki_b64]))
        used_cosign_challenge: Optional[str] = None
        assertion = extract_webauthn_assertion(record)

        cosign_required = (
            self._is_live_mode
            or self.require_webauthn_cosign
            or self.require_passkey_cosign
            or bool(combined_pinned_keys)
            or assertion is not None
        )
        if cosign_required:
            if self._is_live_mode and not combined_pinned_keys:
                detail = (
                    "LIVE_PASSKEY_PIN_REQUIRED: Live execution requires at least one locally pinned "
                    "WebAuthn passkey SPKI public key (operator_passkey_spki_b64 / trusted_passkey_spki_b64)."
                )
                self._report_execution(
                    approval_id,
                    {"status": "cosign_rejected", "detail": detail},
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "cosign_rejected",
                    "detail": detail,
                }

            cosign_ok, cosign_detail = verify_webauthn_assertion(
                record,
                combined_pinned_keys,
                expected_rp_id=self._webauthn_rp_id,
                expected_origin=self._webauthn_origin,
                trusted_credential_ids=self._trusted_credential_ids or None,
            )
            if cosign_ok and assertion is not None:
                ch = extract_client_challenge(assertion)
                if ch and ch in self._used_passkey_challenges:
                    cosign_ok = False
                    cosign_detail = "Replayed WebAuthn passkey challenge rejected by local worker."
                elif ch:
                    used_cosign_challenge = ch

            if not cosign_ok:
                detail = f"Operator hardware passkey co-signature verification failed: {cosign_detail}"
                self._report_execution(
                    approval_id,
                    {"status": "cosign_rejected", "detail": detail},
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "cosign_rejected",
                    "detail": detail,
                }

        # 3b. Fetch fresh live quote from IBKR.
        quote = self.adapter.get_quote(symbol)
        fresh_price = self._resolve_reference_price(side, quote)
        if fresh_price is None:
            detail = f"No fresh live quote available for {symbol} ({side}); refusing to execute blind."
            self._report_execution(
                approval_id,
                {"status": "slippage_rejected", "detail": detail, "limit_price": limit_price},
            )
            return {
                "approval_id": approval_id,
                "symbol": symbol,
                "status": "slippage_rejected",
                "fresh_price": None,
                "limit_price": limit_price,
                "detail": detail,
            }

        # 3c. Validate fresh reference price against approved limit_price.
        if side == "BUY":
            adverse_slippage_bps = (fresh_price - limit_price) / limit_price * 10_000.0
        else:
            adverse_slippage_bps = (limit_price - fresh_price) / limit_price * 10_000.0
        abs_gap_bps = abs(fresh_price - limit_price) / limit_price * 10_000.0
        slippage_bps = adverse_slippage_bps
        if adverse_slippage_bps > self.max_slippage_bps or abs_gap_bps > self.max_favorable_gap_bps:
            if adverse_slippage_bps > self.max_slippage_bps:
                detail = (
                    f"Fresh {side} price {fresh_price:.4f} deviates {adverse_slippage_bps:.1f} bps adversely from approved "
                    f"limit {limit_price:.4f} (max {self.max_slippage_bps:.1f} bps)."
                )
            else:
                detail = (
                    f"Fresh {side} price {fresh_price:.4f} deviates {abs_gap_bps:.1f} bps from approved "
                    f"limit {limit_price:.4f}, exceeding stale-quote sanity bound ({self.max_favorable_gap_bps:.1f} bps)."
                )
            self._report_execution(
                approval_id,
                {
                    "status": "slippage_rejected",
                    "detail": detail,
                    "fresh_price": fresh_price,
                    "limit_price": limit_price,
                    "slippage_bps": round(slippage_bps, 2),
                },
            )
            return {
                "approval_id": approval_id,
                "symbol": symbol,
                "status": "slippage_rejected",
                "fresh_price": fresh_price,
                "limit_price": limit_price,
                "slippage_bps": round(slippage_bps, 2),
                "detail": detail,
            }

        # 3d. Verify Cloud-issued Ed25519 policy ticket (split-key mode) or evaluate via firewall.
        try:
            order_type = OrderType(order_type_raw)
        except ValueError:
            order_type = OrderType.LIMIT

        ticket_verifier = getattr(self.adapter.runtime, "ticket_verifier", None)
        if ticket_verifier is not None:
            # Hard-block immediately if kill-switch is latched.
            if self._is_kill_switch_tripped():
                detail = "Kill-switch is tripped (hard-blocked)."
                self._report_execution(
                    approval_id,
                    {
                        "status": "firewall_denied",
                        "detail": detail,
                        "reason_codes": ["KILL_SWITCH_TRIPPED"],
                        "reasons": [detail],
                    },
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "firewall_denied",
                    "fresh_price": fresh_price,
                    "reason_codes": ["KILL_SWITCH_TRIPPED"],
                    "reasons": [detail],
                    "detail": detail,
                }

            raw_ticket = (
                record.get("policy_ticket")
                or record.get("signed_attestation")
                or record.get("attestation")
            )
            if raw_ticket is None:
                detail = "SPLIT_KEY_TICKET_REQUIRED: Missing Cloud-issued Ed25519 policy ticket."
                self._report_execution(
                    approval_id,
                    {
                        "status": "firewall_denied",
                        "detail": detail,
                        "reason_codes": ["SPLIT_KEY_TICKET_REQUIRED"],
                        "reasons": [detail],
                    },
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "firewall_denied",
                    "fresh_price": fresh_price,
                    "reason_codes": ["SPLIT_KEY_TICKET_REQUIRED"],
                    "reasons": [detail],
                    "detail": detail,
                }

            try:
                ticket = (
                    raw_ticket
                    if isinstance(raw_ticket, SignedAttestation)
                    else SignedAttestation.model_validate(raw_ticket)
                )
            except Exception as exc:
                detail = f"SPLIT_KEY_TICKET_INVALID: Malformed Ed25519 policy ticket ({exc})."
                self._report_execution(
                    approval_id,
                    {
                        "status": "firewall_denied",
                        "detail": detail,
                        "reason_codes": ["SPLIT_KEY_TICKET_INVALID"],
                        "reasons": [detail],
                    },
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "firewall_denied",
                    "fresh_price": fresh_price,
                    "reason_codes": ["SPLIT_KEY_TICKET_INVALID"],
                    "reasons": [detail],
                    "detail": detail,
                }

            raw_proposal_id = str(record.get("proposal_id") or nested.get("proposal_id") or "").strip()
            if raw_proposal_id and raw_proposal_id != ticket.proposal_id:
                detail = "SPLIT_KEY_TICKET_INVALID: proposal_id mismatch between record and policy ticket."
                self._report_execution(
                    approval_id,
                    {
                        "status": "firewall_denied",
                        "detail": detail,
                        "reason_codes": ["ORDER_HASH_MISMATCH"],
                        "reasons": [detail],
                    },
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "firewall_denied",
                    "fresh_price": fresh_price,
                    "reason_codes": ["ORDER_HASH_MISMATCH"],
                    "reasons": [detail],
                    "detail": detail,
                }

            proposal = TradeProposal(
                proposal_id=ticket.proposal_id,
                agent_id=agent_id,
                venue=_IBKR_VENUE,
                symbol=symbol,
                side=Side(side),
                order_type=order_type,
                quantity=quantity,
                limit_price=limit_price,
                stop_price=stop_price if (stop_price is not None and stop_price > 0) else None,
                target_price=target_price if (target_price is not None and target_price > 0) else None,
                reasoning_trace=reasoning_trace,
            )

            ticket_ok, ticket_code = ticket_verifier.verify(attestation=ticket, proposal=proposal)
            if not ticket_ok:
                detail = f"Cloud Ed25519 policy ticket rejected: {ticket_code}"
                self._report_execution(
                    approval_id,
                    {
                        "status": "firewall_denied",
                        "detail": detail,
                        "reason_codes": [ticket_code],
                        "reasons": [detail],
                    },
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "firewall_denied",
                    "fresh_price": fresh_price,
                    "reason_codes": [ticket_code],
                    "reasons": [detail],
                    "detail": detail,
                }
            attestation = ticket
        else:
            proposal = TradeProposal(
                agent_id=agent_id,
                venue=_IBKR_VENUE,
                symbol=symbol,
                side=Side(side),
                order_type=order_type,
                quantity=quantity,
                limit_price=limit_price,
                stop_price=stop_price if (stop_price is not None and stop_price > 0) else None,
                target_price=target_price if (target_price is not None and target_price > 0) else None,
                reasoning_trace=reasoning_trace,
            )
            if self._is_kill_switch_tripped():
                detail = "Kill-switch is tripped (hard-blocked)."
                self._report_execution(
                    approval_id,
                    {
                        "status": "firewall_denied",
                        "detail": detail,
                        "reason_codes": ["KILL_SWITCH_TRIPPED"],
                        "reasons": [detail],
                    },
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "firewall_denied",
                    "fresh_price": fresh_price,
                    "reason_codes": ["KILL_SWITCH_TRIPPED"],
                    "reasons": [detail],
                    "detail": detail,
                }
            portfolio = self.adapter.build_portfolio_snapshot()
            decision = self.adapter.runtime.evaluate_proposal(proposal=proposal, portfolio=portfolio)
            if not decision.approved or decision.attestation is None:
                detail = "; ".join(decision.reasons) if decision.reasons else ",".join(decision.reason_codes)
                self._report_execution(
                    approval_id,
                    {
                        "status": "firewall_denied",
                        "detail": detail or "Denied by clearfills-firewall under live portfolio state.",
                        "reason_codes": list(decision.reason_codes),
                        "reasons": list(decision.reasons),
                    },
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "firewall_denied",
                    "fresh_price": fresh_price,
                    "reason_codes": list(decision.reason_codes),
                    "reasons": list(decision.reasons),
                    "detail": detail,
                }
            attestation = decision.attestation

        # 3e. Dry-run short-circuit: validated & attested without submitting to IBKR.
        if self.dry_run:
            return {
                "approval_id": approval_id,
                "symbol": symbol,
                "status": "dry_run_ready",
                "fresh_price": fresh_price,
                "limit_price": limit_price,
                "slippage_bps": round(slippage_bps, 2),
                "attestation_id": attestation.attestation_id,
            }

        # 3f. Submit freshly attested order to IBKR and report honest receipt to ClearFills Cloud.
        try:
            receipt = self.adapter.submit_attested_order(proposal=proposal, attestation=attestation)
        except (LiveExecutionSafetyError, Exception) as exc:
            detail = sanitize_text(str(exc) or type(exc).__name__)
            self._report_execution(
                approval_id,
                {
                    "status": "execution_failed",
                    "detail": detail,
                    "attestation_id": attestation.attestation_id,
                },
            )
            return {
                "approval_id": approval_id,
                "symbol": symbol,
                "status": "execution_failed",
                "fresh_price": fresh_price,
                "attestation_id": attestation.attestation_id,
                "detail": detail,
            }

        if used_cosign_challenge is not None:
            self._used_passkey_challenges.add(used_cosign_challenge)

        receipt_dict = receipt.model_dump(mode="json")
        receipt_dict["attestation_id"] = attestation.attestation_id
        receipt_dict["order_ids"] = list(receipt.order_ids)
        broker_order_id = str(receipt.order_ids[0]) if receipt.order_ids else None

        has_actual_fill = (
            receipt.filled_qty > 0.0
            and receipt.avg_fill_price is not None
            and receipt.avg_fill_price > 0.0
        )
        if has_actual_fill:
            execution_status = "filled"
            actual_fill_price: Optional[float] = float(receipt.avg_fill_price)
            fill_price: Optional[float] = actual_fill_price
        else:
            execution_status = "submitted"
            actual_fill_price = None
            fill_price = None

        report_payload = {
            "broker_order_id": broker_order_id,
            "quoted_reference_price": fresh_price,
            "fill_price": fill_price,
            "actual_fill_price": actual_fill_price,
            "filled_qty": receipt.filled_qty,
            "status": execution_status,
            "receipt": receipt_dict,
        }
        self._report_execution(approval_id, report_payload)

        return {
            "approval_id": approval_id,
            "symbol": symbol,
            "status": execution_status,
            "broker_order_id": broker_order_id,
            "quoted_reference_price": fresh_price,
            "fill_price": fill_price,
            "actual_fill_price": actual_fill_price,
            "filled_qty": receipt.filled_qty,
            "fresh_price": fresh_price,
            "slippage_bps": round(slippage_bps, 2),
            "attestation_id": attestation.attestation_id,
            "receipt": receipt_dict,
        }

    def send_heartbeat(self) -> None:
        """Best-effort worker heartbeat to ClearFills Cloud (never crashes the poll loop)."""
        self._last_heartbeat_at = time.monotonic()
        try:
            account_id = self.adapter.runtime.config.ibkr.account_id or ""
            payload = {
                "worker_id": self.worker_id,
                "venue": _IBKR_VENUE,
                "execution_mode": self.adapter._mode,
                "account_masked": mask_account_id(account_id),
                "max_slippage_bps": self.max_slippage_bps,
                "dry_run": self.dry_run,
            }
            self._cloud_request("POST", "/api/v1/cloud/worker/heartbeat", payload)
        except Exception:
            # Best-effort telemetry; never crash the poll loop if offline or endpoint returns 404.
            pass

    def poll_once(self) -> list[dict[str, Any]]:
        """Monitor mark-to-market drawdown, fetch approved IBKR orders once, and process each safely."""
        now = time.monotonic()
        if self._last_heartbeat_at is None or (now - self._last_heartbeat_at) >= self._heartbeat_interval_sec:
            self.send_heartbeat()

        # Check live mark-to-market drawdown on EVERY poll cycle (even with 0 pending orders).
        self.check_drawdown_and_latch_killswitch()

        raw = self._cloud_request("GET", "/api/v1/cloud/approvals?status=approved")
        approvals = _extract_approvals(raw)

        results: list[dict[str, Any]] = []
        for record in approvals:
            nested = _nested_order_fields(record)
            venue = str(record.get("venue") or nested.get("venue") or "").strip().lower()
            if venue != _IBKR_VENUE:
                continue
            approval_id = str(record.get("approval_id") or record.get("id") or "").strip()
            if not approval_id:
                continue
            results.append(self._process_approval(record))
        return results

    def run_forever(
        self,
        poll_interval_sec: float = 3.0,
        *,
        stdout: TextIO = sys.stdout,
    ) -> None:
        """Continuously poll for approved IBKR orders until interrupted."""
        mode_tag = "DRY-RUN" if self.dry_run else self.adapter.execution_mode.upper()
        stdout.write(
            f"[clearfills-desk watch] mode={mode_tag} api={self.api_url} "
            f"interval={poll_interval_sec:.1f}s max_slippage={self.max_slippage_bps:.1f}bps\n"
        )
        stdout.flush()
        try:
            while True:
                try:
                    outcomes = self.poll_once()
                    for item in outcomes:
                        stdout.write(
                            f"[clearfills-desk watch] approval={item.get('approval_id')} "
                            f"symbol={item.get('symbol')} status={item.get('status')}"
                            + (
                                f" order_id={item.get('broker_order_id')}"
                                if item.get("broker_order_id")
                                else ""
                            )
                            + (f" detail={item.get('detail')}" if item.get("detail") else "")
                            + "\n"
                        )
                        stdout.flush()
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    stdout.write(f"[clearfills-desk watch] poll_error={sanitize_text(str(exc))}\n")
                    stdout.flush()
                time.sleep(max(0.1, float(poll_interval_sec)))
        except KeyboardInterrupt:
            stdout.write("[clearfills-desk watch] stopped.\n")
            stdout.flush()
