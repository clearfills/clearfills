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

import base64
import hashlib
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Callable, Optional, TextIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

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


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64_flexible(data: str) -> bytes:
    """Decode standard base64 or base64url (padded or unpadded) strictly."""
    cleaned = "".join(data.split()).rstrip("=")
    if not cleaned or len(cleaned) % 4 == 1:
        raise ValueError("Invalid base64 encoding.")
    normalized = cleaned.replace("+", "-").replace("/", "_")
    pad = "=" * ((4 - len(normalized) % 4) % 4)
    return base64.urlsafe_b64decode((normalized + pad).encode("ascii"))


def _has_canonical_approval_record_fields(record: dict[str, Any]) -> bool:
    return (
        record.get("created_at") is not None
        and record.get("sleeve") is not None
        and record.get("notional_usd") is not None
    )


def compute_approval_hash(record: dict[str, Any]) -> str:
    """Compute canonical SHA-256 approval_hash matching ClearFills Cloud `ApprovalRecord`."""
    nested = _nested_order_fields(record)
    approval_id = str(record.get("approval_id") or record.get("id") or "").strip()
    symbol = str(record.get("symbol") or nested.get("symbol") or "").strip().upper()
    side = str(record.get("side") or nested.get("side") or "").strip().upper()
    qty_raw = record.get("quantity") if record.get("quantity") is not None else nested.get("quantity")
    quantity = float(qty_raw) if qty_raw is not None else 0.0
    lmt_raw = record.get("limit_price") if record.get("limit_price") is not None else nested.get("limit_price")
    limit_price = float(lmt_raw) if lmt_raw is not None else None
    stp_raw = record.get("stop_price") if record.get("stop_price") is not None else nested.get("stop_price")
    stop_price = round(float(stp_raw), 6) if stp_raw is not None else None
    tgt_raw = record.get("target_price") if record.get("target_price") is not None else nested.get("target_price")
    target_price = round(float(tgt_raw), 6) if tgt_raw is not None else None
    order_type = str(record.get("order_type") or nested.get("order_type") or "LIMIT").strip().upper()
    venue = str(record.get("venue") or nested.get("venue") or _IBKR_VENUE).strip().lower()
    agent_id = str(record.get("agent_id") or nested.get("agent_id") or "agent").strip()

    if _has_canonical_approval_record_fields(record):
        raw_dt = record["created_at"]
        created_iso = (
            raw_dt.isoformat()
            if isinstance(raw_dt, datetime)
            else datetime.fromisoformat(str(raw_dt)).isoformat()
        )
        canonical_obj: dict[str, Any] = {
            "approval_id": approval_id,
            "symbol": symbol,
            "side": side,
            "quantity": quantity,
            "limit_price": limit_price,
            "stop_price": stop_price,
            "target_price": target_price,
            "order_type": order_type,
            "notional_usd": float(record["notional_usd"]),
            "sleeve": str(record["sleeve"]).strip(),
            "venue": venue,
            "attestation_id": record.get("attestation_id"),
            "agent_id": agent_id,
            "created_at": created_iso,
        }
    else:
        canonical_obj = {
            "approval_id": approval_id,
            "symbol": symbol,
            "side": side,
            "quantity": quantity,
            "limit_price": limit_price,
            "stop_price": stop_price,
            "target_price": target_price,
            "order_type": order_type,
            "venue": venue,
            "agent_id": agent_id,
        }

    encoded = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _bundle_order_fields_match_record(record: dict[str, Any], bundle: dict[str, Any]) -> bool:
    """Verify any explicit order fields embedded inside `bundle` match `record`."""
    rec_nested = _nested_order_fields(record)
    bun_nested = bundle.get("order_summary") if isinstance(bundle.get("order_summary"), dict) else {}

    rec_id = str(record.get("approval_id") or record.get("id") or "").strip()
    bun_id = str(bundle.get("approval_id") or "").strip()
    if rec_id and bun_id and rec_id != bun_id:
        return False

    for str_key in ("symbol", "side"):
        bun_val = bundle.get(str_key) if bundle.get(str_key) is not None else bun_nested.get(str_key)
        if bun_val is not None:
            rec_val = record.get(str_key) if record.get(str_key) is not None else rec_nested.get(str_key)
            if str(bun_val).strip().upper() != str(rec_val or "").strip().upper():
                return False

    for num_key in ("quantity", "limit_price"):
        bun_num = _opt_float(
            bundle.get(num_key) if bundle.get(num_key) is not None else bun_nested.get(num_key)
        )
        if bun_num is not None:
            rec_num = _opt_float(
                record.get(num_key) if record.get(num_key) is not None else rec_nested.get(num_key)
            )
            if rec_num is None or abs(bun_num - rec_num) > 1e-6:
                return False

    return True


def verify_operator_passkey_cosignature(
    record: dict[str, Any],
    trusted_spki_keys_b64: list[str],
) -> tuple[bool, str]:
    """Independently verify a WebAuthn Touch ID / YubiKey co-signature on the local desk.

    Fails closed when `trusted_spki_keys_b64` is non-empty and the assertion bundle is
    missing, malformed, missing the User Present flag, mismatched against
    `base64url(sha256(f"{challenge_nonce}:{approval_hash}"))`, tampered relative to the
    canonical order fields, or not signed by a pinned ECDSA P-256 / RSA public key.
    """
    pinned_keys = [k.strip() for k in trusted_spki_keys_b64 if isinstance(k, str) and k.strip()]
    if not pinned_keys:
        return True, "no_pinned_passkey_configured"

    if not isinstance(record, dict):
        return False, "Approval record must be a dictionary."

    raw_bundle = (
        record.get("passkey_assertion_bundle")
        or record.get("passkey_assertion")
        or record.get("webauthn_proof")
        or record.get("passkey_proof")
    )
    if not isinstance(raw_bundle, dict) or not raw_bundle:
        return False, "Missing passkey_assertion_bundle on approval record."
    bundle = raw_bundle

    parsed_keys: list[ec.EllipticCurvePublicKey | rsa.RSAPublicKey] = []
    for raw_key in pinned_keys:
        try:
            if raw_key.startswith("-----BEGIN"):
                pub = serialization.load_pem_public_key(raw_key.encode("utf-8"))
            else:
                pub = serialization.load_der_public_key(_decode_b64_flexible(raw_key))
            if isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1):
                parsed_keys.append(pub)
            elif isinstance(pub, rsa.RSAPublicKey):
                parsed_keys.append(pub)
        except Exception:
            continue

    if not parsed_keys:
        return False, "No valid DER SPKI ECDSA P-256 or RSA public keys in operator_passkey_spki_b64."

    raw_auth_data = bundle.get("authenticator_data")
    raw_client_data = bundle.get("client_data_json")
    raw_signature = bundle.get("signature")
    raw_challenge = bundle.get("challenge")
    if (
        not isinstance(raw_auth_data, str)
        or not raw_auth_data.strip()
        or not isinstance(raw_client_data, str)
        or not raw_client_data.strip()
        or not isinstance(raw_signature, str)
        or not raw_signature.strip()
        or not isinstance(raw_challenge, str)
        or not raw_challenge.strip()
    ):
        return (
            False,
            "Missing required WebAuthn fields (authenticator_data, client_data_json, signature, challenge).",
        )

    challenge = raw_challenge.strip()
    try:
        auth_data = _decode_b64_flexible(raw_auth_data)
        client_data_bytes = _decode_b64_flexible(raw_client_data)
        sig_bytes = _decode_b64_flexible(raw_signature)
    except Exception as exc:
        return False, f"Malformed base64 WebAuthn assertion payload: {exc}"

    if len(auth_data) < 37:
        return False, "Invalid WebAuthn authenticatorData (must be at least 37 bytes)."
    if (auth_data[32] & 0x01) == 0:
        return False, "WebAuthn User Present (UP) bit is not set."

    try:
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except Exception:
        return False, "Invalid JSON in WebAuthn clientDataJSON."
    if not isinstance(client_data, dict):
        return False, "WebAuthn clientDataJSON must be an object."
    if client_data.get("type") != "webauthn.get":
        return False, f"Invalid WebAuthn clientDataJSON.type {client_data.get('type')!r} (expected 'webauthn.get')."
    if str(client_data.get("challenge") or "").strip() != challenge:
        return False, "WebAuthn clientDataJSON.challenge does not match assertion challenge."

    record_hash = str(record.get("approval_hash") or "").strip()
    bundle_hash = str(bundle.get("approval_hash") or "").strip()
    if record_hash and bundle_hash and record_hash != bundle_hash:
        return False, "approval_hash mismatch between approval record and passkey_assertion_bundle."
    approval_hash = record_hash or bundle_hash

    if approval_hash and _has_canonical_approval_record_fields(record):
        try:
            recomputed_hash = compute_approval_hash(record)
        except Exception as exc:
            return False, f"Failed computing canonical approval_hash from order fields: {exc}"
        if recomputed_hash != approval_hash:
            return (
                False,
                "Order parameters in approval record do not match approval_hash (tampered order rejected).",
            )

    if not _bundle_order_fields_match_record(record, bundle):
        return False, "Order parameters in approval record do not match passkey_assertion_bundle."

    challenge_nonce = str(bundle.get("challenge_nonce") or record.get("challenge_nonce") or "").strip()
    if bundle.get("challenge_binding") == "sha256(nonce:approval_hash)" and (
        not challenge_nonce or not approval_hash
    ):
        return (
            False,
            "Assertion declares sha256(nonce:approval_hash) binding without challenge_nonce and approval_hash.",
        )
    if challenge_nonce and approval_hash:
        expected_challenge = _b64u_encode(
            hashlib.sha256(f"{challenge_nonce}:{approval_hash}".encode("utf-8")).digest()
        )
        if challenge != expected_challenge:
            return (
                False,
                "WebAuthn challenge mismatch: expected base64url(sha256(challenge_nonce:approval_hash)).",
            )

    signed_payload = auth_data + hashlib.sha256(client_data_bytes).digest()
    for pub_key in parsed_keys:
        try:
            if isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(sig_bytes, signed_payload, ec.ECDSA(hashes.SHA256()))
                return True, "ok"
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(sig_bytes, signed_payload, padding.PKCS1v15(), hashes.SHA256())
                return True, "ok"
        except InvalidSignature:
            continue
        except Exception:
            continue

    return False, "WebAuthn signature did not match any pinned key in operator_passkey_spki_b64."


def _b64u_decode(data: str) -> bytes:
    cleaned = data.strip()
    pad = "=" * ((4 - len(cleaned) % 4) % 4)
    return base64.urlsafe_b64decode(cleaned + pad)


def _derive_order_bound_challenge(nonce_b64: str, approval_hash: str) -> str:
    digest = hashlib.sha256(f"{nonce_b64}:{approval_hash}".encode("utf-8")).digest()
    return _b64u_encode(digest)


def verify_local_webauthn_cosign(
    record: dict[str, Any],
    trusted_spki_b64: list[str],
) -> tuple[bool, str]:
    """Independently verify a hardware WebAuthn ECDSA P-256 / RSA co-signature against locally pinned SPKI keys."""
    pinned_keys = [k.strip() for k in (trusted_spki_b64 or []) if isinstance(k, str) and k.strip()]
    if not pinned_keys:
        return False, "No locally pinned trusted passkey SPKI public keys configured."

    proof = record.get("webauthn_proof")
    if not isinstance(proof, dict):
        proof = record.get("passkey_proof")
    if not isinstance(proof, dict):
        return False, "Missing webauthn_proof on approval record."

    for field in ("authenticator_data", "client_data_json", "signature"):
        val = proof.get(field)
        if not isinstance(val, str) or not val.strip():
            return False, f"Missing or empty webauthn_proof.{field}."

    try:
        auth_data = _b64u_decode(proof["authenticator_data"])
        client_data_bytes = _b64u_decode(proof["client_data_json"])
        sig_bytes = _b64u_decode(proof["signature"])
    except Exception:
        return False, "Malformed base64url payload in webauthn_proof."

    if len(auth_data) < 37:
        return False, "Invalid WebAuthn authenticatorData (too short)."
    if (auth_data[32] & 0x01) == 0:
        return False, "WebAuthn User Present (UP) flag is not set."

    try:
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except Exception:
        return False, "Invalid WebAuthn clientDataJSON."
    if not isinstance(client_data, dict):
        return False, "Invalid WebAuthn clientDataJSON."
    if client_data.get("type") != "webauthn.get":
        return False, "Invalid WebAuthn ceremony type (expected webauthn.get)."

    client_challenge = str(client_data.get("challenge", "")).strip()
    if not client_challenge:
        return False, "Missing challenge in WebAuthn clientDataJSON."

    proof_challenge = proof.get("challenge")
    if isinstance(proof_challenge, str) and proof_challenge.strip() and proof_challenge.strip() != client_challenge:
        return False, "WebAuthn proof challenge does not match clientDataJSON.challenge."

    raw_nonce = proof.get("challenge_nonce") or record.get("challenge_nonce")
    challenge_nonce = raw_nonce.strip() if isinstance(raw_nonce, str) and raw_nonce.strip() else None

    raw_record_hash = record.get("approval_hash")
    record_approval_hash = (
        raw_record_hash.strip() if isinstance(raw_record_hash, str) and raw_record_hash.strip() else None
    )
    raw_proof_hash = proof.get("approval_hash")
    proof_approval_hash = (
        raw_proof_hash.strip() if isinstance(raw_proof_hash, str) and raw_proof_hash.strip() else None
    )

    if record_approval_hash is not None and proof_approval_hash is not None and record_approval_hash != proof_approval_hash:
        return False, "WebAuthn proof approval_hash does not match approval record approval_hash."

    effective_approval_hash = record_approval_hash or proof_approval_hash
    if challenge_nonce is not None and effective_approval_hash is not None:
        expected_challenge = _derive_order_bound_challenge(challenge_nonce, effective_approval_hash)
        if client_challenge != expected_challenge:
            return False, "WebAuthn challenge mismatch: does not match sha256(nonce:approval_hash)."
    elif proof.get("challenge_binding") == "sha256(nonce:approval_hash)":
        return False, "Missing challenge_nonce or approval_hash for order-bound WebAuthn challenge."

    signed_payload = auth_data + hashlib.sha256(client_data_bytes).digest()
    for spki_b64 in pinned_keys:
        try:
            pub_key = serialization.load_der_public_key(_b64u_decode(spki_b64))
        except Exception:
            continue
        try:
            if isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(sig_bytes, signed_payload, ec.ECDSA(hashes.SHA256()))
                return True, "WebAuthn ECDSA co-signature verified against locally pinned key."
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(sig_bytes, signed_payload, padding.PKCS1v15(), hashes.SHA256())
                return True, "WebAuthn RSA co-signature verified against locally pinned key."
        except InvalidSignature:
            continue
        except Exception:
            continue

    return False, "WebAuthn cryptographic signature failed against all locally pinned trusted keys."


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
        max_favorable_gap_bps: float = 1000.0,
        trusted_passkey_spki_b64: Optional[list[str]] = None,
        require_webauthn_cosign: bool = False,
    ) -> None:
        self.adapter = adapter
        self.api_key = api_key.strip()
        self.api_url = (api_url or DEFAULT_CLOUD_API_URL).strip().rstrip("/")
        self.max_slippage_bps = float(max_slippage_bps)
        self.max_favorable_gap_bps = float(max_favorable_gap_bps)
        self.dry_run = bool(dry_run)
        self._cloud_transport = cloud_transport
        self._timeout = float(timeout)
        desk_id = getattr(getattr(getattr(adapter, "runtime", None), "config", None), "desk_id", "desk")
        default_worker_id = f"{desk_id}-{socket.gethostname()}"
        self.worker_id = (worker_id or default_worker_id).strip() or default_worker_id
        self._heartbeat_interval_sec = float(heartbeat_interval_sec)
        self._last_heartbeat_at: Optional[float] = None
        self._used_passkey_challenges: set[str] = set()
        self._trusted_passkey_spki_b64: list[str] = [
            k.strip() for k in (trusted_passkey_spki_b64 or []) if isinstance(k, str) and k.strip()
        ]
        self.require_webauthn_cosign: bool = bool(require_webauthn_cosign)

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

        # 3a-ii. Independent local hardware passkey co-signature check (when operator_passkey_spki_b64 is pinned).
        trusted_keys = getattr(self.adapter.runtime.config, "operator_passkey_spki_b64", [])
        used_cosign_challenge: Optional[str] = None
        if trusted_keys:
            cosign_ok, cosign_reason = verify_operator_passkey_cosignature(record, list(trusted_keys))
            if cosign_ok:
                raw_bundle = (
                    record.get("passkey_assertion_bundle")
                    or record.get("passkey_assertion")
                    or record.get("webauthn_proof")
                    or record.get("passkey_proof")
                )
                if isinstance(raw_bundle, dict):
                    ch = str(raw_bundle.get("challenge") or "").strip()
                    if ch in self._used_passkey_challenges:
                        cosign_ok = False
                        cosign_reason = "Replayed WebAuthn passkey challenge rejected by local worker."
                    elif ch:
                        used_cosign_challenge = ch
            if not cosign_ok:
                detail = f"Operator hardware passkey co-signature verification failed: {cosign_reason}"
                self._report_execution(
                    approval_id,
                    {"status": "execution_failed", "detail": detail},
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "execution_failed",
                    "detail": detail,
                }

        # 3a.5. Independent local hardware WebAuthn co-signature verification (fail closed before IBKR).
        if self.require_webauthn_cosign or self._trusted_passkey_spki_b64:
            cosign_ok, cosign_detail = verify_local_webauthn_cosign(
                record, self._trusted_passkey_spki_b64
            )
            if not cosign_ok:
                self._report_execution(
                    approval_id,
                    {"status": "cosign_rejected", "detail": cosign_detail},
                )
                return {
                    "approval_id": approval_id,
                    "symbol": symbol,
                    "status": "cosign_rejected",
                    "detail": cosign_detail,
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

        # 3c. Validate fresh reference price against approved limit_price (directional adverse slippage + stale-quote sanity bound).
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

        if used_cosign_challenge is not None:
            self._used_passkey_challenges.add(used_cosign_challenge)

        receipt_dict = receipt.model_dump(mode="json")
        receipt_dict["attestation_id"] = attestation.attestation_id
        receipt_dict["order_ids"] = list(receipt.order_ids)
        broker_order_id = str(receipt.order_ids[0]) if receipt.order_ids else None
        fill_price = fresh_price
        report_payload = {
            "broker_order_id": broker_order_id,
            "fill_price": fill_price,
            "status": "submitted",
            "receipt": receipt_dict,
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
