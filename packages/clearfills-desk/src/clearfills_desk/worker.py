"""Approval worker bridging ClearFills Cloud 1-Tap approvals to live/paper IBKR execution.

Solves the 3.5-minute preview attestation TTL expiry:
When an operator approves a trade on ClearFills Cloud (even hours after the original
preview attestation expired), `ApprovalWorker` polls for approved IBKR orders,
atomically claims each order, fetches a fresh live quote, validates slippage against
the approved limit price, re-evaluates the live portfolio through `clearfills-firewall`
to mint a fresh single-use Ed25519 attestation, submits the order via
`IBKRExecutionAdapter.submit_attested_order`, and reports the broker receipt back to
ClearFills Cloud.
"""

from __future__ import annotations

import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional, TextIO

from clearfills_firewall import OrderType, Side, TradeProposal

from .ibkr import IBKRExecutionAdapter, LiveExecutionSafetyError, mask_account_id
from .telemetry import sanitize_text

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


class ApprovalWorker:
    """Polls ClearFills Cloud for approved IBKR orders and executes them with fresh attestations."""

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
    ) -> None:
        self.adapter = adapter
        self.api_key = api_key.strip()
        self.api_url = (api_url or DEFAULT_CLOUD_API_URL).strip().rstrip("/")
        self.max_slippage_bps = float(max_slippage_bps)
        self.dry_run = bool(dry_run)
        self._cloud_transport = cloud_transport
        self._timeout = float(timeout)
        desk_id = getattr(getattr(getattr(adapter, "runtime", None), "config", None), "desk_id", "desk")
        default_worker_id = f"{desk_id}-{socket.gethostname()}"
        self.worker_id = (worker_id or default_worker_id).strip() or default_worker_id
        self._heartbeat_interval_sec = float(heartbeat_interval_sec)
        self._last_heartbeat_at: Optional[float] = None

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
        slippage_bps = abs(fresh_price - limit_price) / limit_price * 10_000.0
        if slippage_bps > self.max_slippage_bps:
            detail = (
                f"Fresh {side} price {fresh_price:.4f} deviates {slippage_bps:.1f} bps from approved "
                f"limit {limit_price:.4f} (max {self.max_slippage_bps:.1f} bps)."
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

        # 3d. Re-evaluate live portfolio through clearfills-firewall to mint a fresh single-use Ed25519 attestation.
        try:
            order_type = OrderType(order_type_raw)
        except ValueError:
            order_type = OrderType.LIMIT

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

        # 3f. Submit freshly attested order to IBKR and report receipt to ClearFills Cloud.
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

        receipt_dict = receipt.model_dump(mode="json")
        broker_order_id = str(receipt.order_ids[0]) if receipt.order_ids else None
        fill_price = fresh_price
        report_payload = {
            "broker_order_id": broker_order_id,
            "fill_price": fill_price,
            "status": "submitted",
            "receipt": receipt_dict,
            "attestation_id": attestation.attestation_id,
            "order_ids": list(receipt.order_ids),
        }
        self._report_execution(approval_id, report_payload)

        return {
            "approval_id": approval_id,
            "symbol": symbol,
            "status": "submitted",
            "broker_order_id": broker_order_id,
            "fill_price": fill_price,
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
        """Fetch approved IBKR orders once and process each one safely."""
        now = time.monotonic()
        if self._last_heartbeat_at is None or (now - self._last_heartbeat_at) >= self._heartbeat_interval_sec:
            self.send_heartbeat()

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
