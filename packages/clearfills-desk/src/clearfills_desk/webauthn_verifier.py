"""Single canonical WebAuthn / Passkey co-signature verifier for ClearFills Desk.

Security invariants (fail-closed):
1. NEVER trusts a public key carried inside the WebAuthn assertion payload.
   Verification requires at least one locally pinned SPKI public key
   (`trusted_passkey_spki_b64`) and optionally pinned `trusted_credential_ids`.
2. Strictly verifies `authenticatorData[:32] == sha256(expected_rp_id)`.
3. Strictly verifies both User Present (`UP`, 0x01) AND User Verified (`UV`, 0x04)
   flags in `authenticatorData[32]`.
4. Strictly verifies `clientDataJSON["type"] == "webauthn.get"` and
   `clientDataJSON["origin"] == expected_origin`.
5. Strictly requires a nonce-bound challenge:
   `base64url(sha256(f"{nonce}:{canonical_order_hash}"))`.
   Nonce-less challenges are ALWAYS rejected.
6. Verifies the ECDSA P-256 (SHA-256) or RSA PKCS1v15 (SHA-256) signature over
   `authenticatorData || sha256(clientDataJSON)` against ONLY locally pinned keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

DEFAULT_WEBAUTHN_RP_ID = "clearfills.com"
DEFAULT_WEBAUTHN_ORIGIN = "https://clearfills.com"
_DEFAULT_VENUE = "ibkr"


def _opt_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        num = float(value)
        return num if num == num else None
    except (TypeError, ValueError):
        return None


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
    venue = str(record.get("venue") or nested.get("venue") or _DEFAULT_VENUE).strip().lower()
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


def canonical_order_digest(approval: dict[str, Any]) -> str:
    """Compute RFC 8785 JCS-style canonical SHA-256 hex digest over core order legs."""
    nested = _nested_order_fields(approval)
    symbol = str(approval.get("symbol") or nested.get("symbol") or "").strip().upper()
    side = str(approval.get("side") or nested.get("side") or "").strip().upper()
    qty_val = _opt_float(
        approval.get("quantity") if approval.get("quantity") is not None else nested.get("quantity")
    )
    lmt_val = _opt_float(
        approval.get("limit_price")
        if approval.get("limit_price") is not None
        else nested.get("limit_price")
    )
    stp_val = _opt_float(
        approval.get("stop_price")
        if approval.get("stop_price") is not None
        else nested.get("stop_price")
    )
    venue = str(approval.get("venue") or nested.get("venue") or _DEFAULT_VENUE).strip().lower()

    canonical_obj: dict[str, Any] = {
        "limit_price": round(lmt_val, 8) if lmt_val is not None else None,
        "quantity": round(qty_val, 8) if qty_val is not None else None,
        "side": side,
        "stop_price": round(stp_val, 8) if stp_val is not None else None,
        "symbol": symbol,
        "venue": venue,
    }
    encoded = json.dumps(
        canonical_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def extract_webauthn_assertion(approval: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Return the first non-empty WebAuthn assertion dictionary present on `approval`."""
    if not isinstance(approval, dict):
        return None
    for key in (
        "webauthn_assertion",
        "passkey_assertion_bundle",
        "passkey_assertion",
        "webauthn_proof",
        "passkey_proof",
    ):
        candidate = approval.get(key)
        if isinstance(candidate, dict) and candidate:
            return candidate
    return None


def extract_client_challenge(assertion: dict[str, Any]) -> Optional[str]:
    """Extract the challenge string from `clientDataJSON` (or fallback `challenge` field)."""
    raw_client_data = assertion.get("clientDataJSON") or assertion.get("client_data_json")
    if isinstance(raw_client_data, str) and raw_client_data.strip():
        try:
            client_data = json.loads(_decode_b64_flexible(raw_client_data).decode("utf-8"))
            if isinstance(client_data, dict):
                ch = str(client_data.get("challenge") or "").strip()
                if ch:
                    return ch
        except Exception:
            pass
    raw_ch = assertion.get("challenge")
    if isinstance(raw_ch, str) and raw_ch.strip():
        return raw_ch.strip()
    return None


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


def _parse_pinned_spki_keys(
    trusted_passkey_spki_b64: list[str],
) -> list[ec.EllipticCurvePublicKey | rsa.RSAPublicKey]:
    """Load locally pinned ECDSA P-256 or RSA SPKI public keys (DER base64/base64url or PEM)."""
    parsed: list[ec.EllipticCurvePublicKey | rsa.RSAPublicKey] = []
    for raw_key in trusted_passkey_spki_b64:
        cleaned = raw_key.strip() if isinstance(raw_key, str) else ""
        if not cleaned:
            continue
        try:
            if cleaned.startswith("-----BEGIN"):
                pub = serialization.load_pem_public_key(cleaned.encode("utf-8"))
            else:
                pub = serialization.load_der_public_key(_decode_b64_flexible(cleaned))
            if isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1):
                parsed.append(pub)
            elif isinstance(pub, rsa.RSAPublicKey):
                parsed.append(pub)
        except Exception:
            continue
    return parsed


def verify_webauthn_assertion(
    record: dict[str, Any],
    trusted_passkey_spki_b64: list[str],
    *,
    expected_rp_id: str = DEFAULT_WEBAUTHN_RP_ID,
    expected_origin: str = DEFAULT_WEBAUTHN_ORIGIN,
    trusted_credential_ids: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """Canonical fail-closed WebAuthn assertion verifier for ClearFills Desk.

    Never trusts any public key embedded in the assertion payload.
    Requires locally pinned SPKI key(s), matching `rpIdHash`, matching `origin`,
    `type == "webauthn.get"`, `UP` (0x01) + `UV` (0x04) flags, and a nonce-bound
    challenge `base64url(sha256(f"{nonce}:{canonical_order_hash}"))`.
    """
    pinned_raw = [k.strip() for k in (trusted_passkey_spki_b64 or []) if isinstance(k, str) and k.strip()]
    if not pinned_raw:
        return False, "No locally pinned trusted passkey SPKI public keys configured (fail-closed)."

    parsed_keys = _parse_pinned_spki_keys(pinned_raw)
    if not parsed_keys:
        return False, "No valid DER SPKI ECDSA P-256 or RSA public keys in trusted_passkey_spki_b64."

    if not isinstance(record, dict):
        return False, "Approval record must be a dictionary."

    assertion = extract_webauthn_assertion(record)
    if assertion is None:
        return False, "Missing webauthn_proof / passkey_assertion_bundle on approval record."

    # Optional pinned credential ID allowlist
    allowed_creds = {
        c.strip() for c in (trusted_credential_ids or []) if isinstance(c, str) and c.strip()
    }
    if allowed_creds:
        cred_id = str(assertion.get("credential_id") or assertion.get("credentialId") or "").strip()
        if not cred_id or cred_id not in allowed_creds:
            return (
                False,
                "WebAuthn credential_id is missing or not in locally pinned trusted_credential_ids.",
            )

    raw_auth_data = assertion.get("authenticatorData") or assertion.get("authenticator_data")
    raw_client_data = assertion.get("clientDataJSON") or assertion.get("client_data_json")
    raw_signature = assertion.get("signature")

    if (
        not isinstance(raw_auth_data, str)
        or not raw_auth_data.strip()
        or not isinstance(raw_client_data, str)
        or not raw_client_data.strip()
        or not isinstance(raw_signature, str)
        or not raw_signature.strip()
    ):
        return (
            False,
            "Missing required WebAuthn assertion fields (authenticatorData, clientDataJSON, signature).",
        )

    try:
        auth_data = _decode_b64_flexible(raw_auth_data)
        client_data_bytes = _decode_b64_flexible(raw_client_data)
        sig_bytes = _decode_b64_flexible(raw_signature)
    except Exception as exc:
        return False, f"Malformed base64 WebAuthn assertion payload: {exc}"

    if len(auth_data) < 37:
        return False, "Invalid WebAuthn authenticatorData (must be at least 37 bytes)."

    # 1. Strict rpIdHash verification
    rp_id_clean = (expected_rp_id or "").strip()
    if not rp_id_clean:
        return False, "expected_rp_id must be non-empty."
    expected_rp_hash = hashlib.sha256(rp_id_clean.encode("utf-8")).digest()
    if not hmac.compare_digest(auth_data[:32], expected_rp_hash):
        return False, f"WebAuthn rpIdHash mismatch (expected rpId={rp_id_clean!r})."

    # 2. Strict UP (0x01) AND UV (0x04) flag verification
    flags = auth_data[32]
    if (flags & 0x01) == 0:
        return False, "WebAuthn User Present (UP) flag is not set."
    if (flags & 0x04) == 0:
        return False, "WebAuthn User Verified (UV) flag is required and not set."

    # 3. Strict clientDataJSON parsing, type, origin, and challenge checks
    try:
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except Exception:
        return False, "Invalid JSON in WebAuthn clientDataJSON."
    if not isinstance(client_data, dict):
        return False, "WebAuthn clientDataJSON must be a JSON object."

    if client_data.get("type") != "webauthn.get":
        return (
            False,
            f"Invalid WebAuthn clientDataJSON.type {client_data.get('type')!r} (expected 'webauthn.get').",
        )

    origin_clean = (expected_origin or "").strip()
    if not origin_clean:
        return False, "expected_origin must be non-empty."
    actual_origin = str(client_data.get("origin") or "").strip()
    if actual_origin != origin_clean:
        return (
            False,
            f"Invalid WebAuthn clientDataJSON.origin {actual_origin!r} (expected {origin_clean!r}).",
        )

    client_challenge = str(client_data.get("challenge") or "").strip()
    if not client_challenge:
        return False, "Missing challenge in WebAuthn clientDataJSON."

    explicit_challenge = assertion.get("challenge")
    if (
        isinstance(explicit_challenge, str)
        and explicit_challenge.strip()
        and explicit_challenge.strip() != client_challenge
    ):
        return False, "WebAuthn assertion challenge does not match clientDataJSON.challenge."

    # 4. Order parameter integrity & mandatory nonce-bound challenge verification
    if not _bundle_order_fields_match_record(record, assertion):
        return False, "Order parameters in approval record do not match WebAuthn assertion bundle."

    raw_nonce = assertion.get("challenge_nonce") or record.get("challenge_nonce")
    challenge_nonce = raw_nonce.strip() if isinstance(raw_nonce, str) and raw_nonce.strip() else ""
    if not challenge_nonce:
        return (
            False,
            "Missing challenge_nonce: nonce-less WebAuthn challenges are rejected (expected sha256(nonce:approval_hash)).",
        )

    record_hash = str(record.get("approval_hash") or "").strip()
    bundle_hash = str(assertion.get("approval_hash") or "").strip()
    if record_hash and bundle_hash and record_hash != bundle_hash:
        return False, "approval_hash mismatch between approval record and WebAuthn assertion."
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

    valid_challenges: set[str] = set()
    if approval_hash:
        valid_challenges.add(
            _b64u_encode(hashlib.sha256(f"{challenge_nonce}:{approval_hash}".encode("utf-8")).digest())
        )
    else:
        order_digest = canonical_order_digest(record)
        valid_challenges.add(
            _b64u_encode(hashlib.sha256(f"{challenge_nonce}:{order_digest}".encode("utf-8")).digest())
        )
        if _has_canonical_approval_record_fields(record):
            recomputed_approval_hash = compute_approval_hash(record)
            valid_challenges.add(
                _b64u_encode(
                    hashlib.sha256(
                        f"{challenge_nonce}:{recomputed_approval_hash}".encode("utf-8")
                    ).digest()
                )
            )

    if not any(hmac.compare_digest(client_challenge, expected) for expected in valid_challenges):
        return (
            False,
            "WebAuthn challenge mismatch: expected base64url(sha256(nonce:approval_hash)).",
        )

    # 5. Cryptographic signature verification against ONLY locally pinned public keys
    signed_payload = auth_data + hashlib.sha256(client_data_bytes).digest()
    for pub_key in parsed_keys:
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
