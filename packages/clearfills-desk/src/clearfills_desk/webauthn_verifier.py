"""Single canonical WebAuthn / Passkey co-signature verifier for ClearFills Desk.

Delegates core WebAuthn assertion verification (CBOR/COSE key handling, `rpIdHash`,
`UP` + `UV` flags, `clientDataJSON` type/origin/challenge, signature verification,
and monotonic `signCount` rollback / cloned authenticator protection) to the vetted
`py_webauthn` (`webauthn`) library.

Security invariants (fail-closed):
1. NEVER trusts a public key carried inside the WebAuthn assertion payload.
   Verification requires at least one locally pinned SPKI public key
   (`trusted_passkey_spki_b64`) converted locally to COSE CBOR bytes, and
   optionally pinned `trusted_credential_ids`.
2. Strictly verifies `authenticatorData[:32] == sha256(expected_rp_id)`.
3. Strictly verifies both User Present (`UP`, 0x01) AND User Verified (`UV`, 0x04)
   flags via `require_user_verification=True`.
4. Strictly verifies `clientDataJSON["type"] == "webauthn.get"` and
   `clientDataJSON["origin"] == expected_origin`.
5. Strictly requires a nonce-bound challenge:
   `base64url(sha256(f"{nonce}:{canonical_order_hash}"))`.
   Nonce-less challenges are ALWAYS rejected.
6. Enforces monotonic `sign_count` rollback protection via `py_webauthn`
   (`credential_current_sign_count`) and returns `new_sign_count` on
   `WebAuthnVerificationResult` so callers can persist per-credential counters.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime
from typing import Any, Optional

import cbor2
import webauthn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier, COSECRV, COSEKey, COSEKTY
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
)

DEFAULT_WEBAUTHN_RP_ID = "clearfills.com"
DEFAULT_WEBAUTHN_ORIGIN = "https://clearfills.com"
_DEFAULT_VENUE = "ibkr"


class WebAuthnVerificationResult(tuple):
    """2-tuple `(verified, detail)` carrying verified `new_sign_count` metadata.

    Unpacks cleanly as `ok, detail = verify_webauthn_assertion(...)` for full
    backwards compatibility while also exposing `.verified`, `.detail`,
    `.new_sign_count`, `.credential_id`, and `.user_verified`.
    """

    verified: bool
    detail: str
    new_sign_count: Optional[int]
    credential_id: Optional[str]
    user_verified: bool

    def __new__(
        cls,
        verified: bool,
        detail: str,
        *,
        new_sign_count: Optional[int] = None,
        credential_id: Optional[str] = None,
        user_verified: bool = False,
    ) -> "WebAuthnVerificationResult":
        obj = super().__new__(cls, (bool(verified), str(detail)))
        return obj

    def __init__(
        self,
        verified: bool,
        detail: str,
        *,
        new_sign_count: Optional[int] = None,
        credential_id: Optional[str] = None,
        user_verified: bool = False,
    ) -> None:
        self.verified = bool(verified)
        self.detail = str(detail)
        self.new_sign_count = new_sign_count
        self.credential_id = credential_id
        self.user_verified = bool(user_verified)


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


def extract_credential_id(assertion: dict[str, Any]) -> str:
    """Extract the credential ID string from a WebAuthn assertion dictionary."""
    if not isinstance(assertion, dict):
        return ""
    for key in ("credential_id", "credentialId", "id"):
        val = assertion.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


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


def spki_public_key_to_cose(pub_key: ec.EllipticCurvePublicKey | rsa.RSAPublicKey) -> bytes:
    """Convert a locally pinned ECDSA P-256 or RSA public key into CBOR-encoded COSE bytes."""
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        if not isinstance(pub_key.curve, ec.SECP256R1):
            raise ValueError("Only ECDSA P-256 (SECP256R1) elliptic curve keys are supported.")
        nums = pub_key.public_numbers()
        cose_map: dict[int, Any] = {
            int(COSEKey.KTY): int(COSEKTY.EC2),
            int(COSEKey.ALG): int(COSEAlgorithmIdentifier.ECDSA_SHA_256),
            int(COSEKey.CRV): int(COSECRV.P256),
            int(COSEKey.X): nums.x.to_bytes(32, "big"),
            int(COSEKey.Y): nums.y.to_bytes(32, "big"),
        }
        return cbor2.dumps(cose_map)
    if isinstance(pub_key, rsa.RSAPublicKey):
        nums = pub_key.public_numbers()
        n_len = max(1, (nums.n.bit_length() + 7) // 8)
        e_len = max(1, (nums.e.bit_length() + 7) // 8)
        cose_map = {
            int(COSEKey.KTY): int(COSEKTY.RSA),
            int(COSEKey.ALG): int(COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256),
            int(COSEKey.N): nums.n.to_bytes(n_len, "big"),
            int(COSEKey.E): nums.e.to_bytes(e_len, "big"),
        }
        return cbor2.dumps(cose_map)
    raise ValueError(f"Unsupported pinned public key type: {type(pub_key).__name__}")


def _parse_pinned_spki_cose_keys(
    trusted_passkey_spki_b64: list[str],
) -> list[tuple[str, bytes]]:
    """Load locally pinned ECDSA P-256 or RSA SPKI keys and convert each to `(key_kind, cose_bytes)`."""
    parsed: list[tuple[str, bytes]] = []
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
                parsed.append(("ECDSA", spki_public_key_to_cose(pub)))
            elif isinstance(pub, rsa.RSAPublicKey):
                parsed.append(("RSA", spki_public_key_to_cose(pub)))
        except Exception:
            continue
    return parsed


def _format_webauthn_error(
    err_msg: str,
    *,
    expected_rp_id: str,
    expected_origin: str,
) -> str:
    low = err_msg.lower()
    if "rp id hash" in low:
        return f"WebAuthn rpIdHash mismatch (expected rpId={expected_rp_id!r}): {err_msg}"
    if "user was not present" in low:
        return f"WebAuthn User Present (UP) flag is not set: {err_msg}"
    if "user verification" in low:
        return f"WebAuthn User Verified (UV) flag is required and not set: {err_msg}"
    if "sign count" in low:
        return f"WebAuthn sign_count rollback / cloned authenticator detected: {err_msg}"
    if "client data type" in low:
        return f"Invalid WebAuthn clientDataJSON.type (expected 'webauthn.get'): {err_msg}"
    if "client data origin" in low:
        return f"Invalid WebAuthn clientDataJSON.origin (expected {expected_origin!r}): {err_msg}"
    if "client data challenge" in low:
        return f"WebAuthn challenge mismatch: expected base64url(sha256(nonce:approval_hash)) ({err_msg})."
    return f"WebAuthn verification failed: {err_msg}"


def verify_webauthn_assertion(
    record: dict[str, Any],
    trusted_passkey_spki_b64: list[str],
    *,
    expected_rp_id: str = DEFAULT_WEBAUTHN_RP_ID,
    expected_origin: str = DEFAULT_WEBAUTHN_ORIGIN,
    trusted_credential_ids: Optional[list[str]] = None,
    current_sign_count: int = 0,
) -> WebAuthnVerificationResult:
    """Canonical fail-closed WebAuthn assertion verifier backed by `py_webauthn`.

    Never trusts any public key embedded in the assertion payload.
    Converts locally pinned SPKI key(s) to COSE CBOR and delegates verification
    to `webauthn.verify_authentication_response` with strict `rpId`, `origin`,
    `require_user_verification=True`, mandatory nonce-bound challenge
    `base64url(sha256(f"{nonce}:{canonical_order_hash}"))`, and monotonic
    `sign_count` rollback protection (`credential_current_sign_count`).
    """
    if not isinstance(current_sign_count, int) or isinstance(current_sign_count, bool) or current_sign_count < 0:
        return WebAuthnVerificationResult(False, "current_sign_count must be a non-negative integer.")

    pinned_raw = [k.strip() for k in (trusted_passkey_spki_b64 or []) if isinstance(k, str) and k.strip()]
    if not pinned_raw:
        return WebAuthnVerificationResult(
            False, "No locally pinned trusted passkey SPKI public keys configured (fail-closed)."
        )

    parsed_cose_keys = _parse_pinned_spki_cose_keys(pinned_raw)
    if not parsed_cose_keys:
        return WebAuthnVerificationResult(
            False, "No valid DER SPKI ECDSA P-256 or RSA public keys in trusted_passkey_spki_b64."
        )

    if not isinstance(record, dict):
        return WebAuthnVerificationResult(False, "Approval record must be a dictionary.")

    assertion = extract_webauthn_assertion(record)
    if assertion is None:
        return WebAuthnVerificationResult(
            False, "Missing webauthn_proof / passkey_assertion_bundle on approval record."
        )

    cred_id = extract_credential_id(assertion)

    # Optional pinned credential ID allowlist
    allowed_creds = {
        c.strip() for c in (trusted_credential_ids or []) if isinstance(c, str) and c.strip()
    }
    if allowed_creds:
        if not cred_id or cred_id not in allowed_creds:
            return WebAuthnVerificationResult(
                False,
                "WebAuthn credential_id is missing or not in locally pinned trusted_credential_ids.",
            )

    rp_id_clean = (expected_rp_id or "").strip()
    if not rp_id_clean:
        return WebAuthnVerificationResult(False, "expected_rp_id must be non-empty.")

    origin_clean = (expected_origin or "").strip()
    if not origin_clean:
        return WebAuthnVerificationResult(False, "expected_origin must be non-empty.")

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
        return WebAuthnVerificationResult(
            False,
            "Missing required WebAuthn assertion fields (authenticatorData, clientDataJSON, signature).",
        )

    try:
        auth_data = _decode_b64_flexible(raw_auth_data)
        client_data_bytes = _decode_b64_flexible(raw_client_data)
        sig_bytes = _decode_b64_flexible(raw_signature)
    except Exception as exc:
        return WebAuthnVerificationResult(False, f"Malformed base64 WebAuthn assertion payload: {exc}")

    if len(auth_data) < 37:
        return WebAuthnVerificationResult(
            False, "Invalid WebAuthn authenticatorData (must be at least 37 bytes)."
        )

    # Parse clientDataJSON to validate explicit challenge consistency & select nonce-bound expected challenge bytes.
    try:
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except Exception:
        return WebAuthnVerificationResult(False, "Invalid JSON in WebAuthn clientDataJSON.")
    if not isinstance(client_data, dict):
        return WebAuthnVerificationResult(False, "WebAuthn clientDataJSON must be a JSON object.")

    client_challenge = str(client_data.get("challenge") or "").strip()
    if not client_challenge:
        return WebAuthnVerificationResult(False, "Missing challenge in WebAuthn clientDataJSON.")

    explicit_challenge = assertion.get("challenge")
    if (
        isinstance(explicit_challenge, str)
        and explicit_challenge.strip()
        and explicit_challenge.strip() != client_challenge
    ):
        return WebAuthnVerificationResult(
            False, "WebAuthn assertion challenge does not match clientDataJSON.challenge."
        )

    # Order parameter integrity & mandatory nonce-bound challenge derivation
    if not _bundle_order_fields_match_record(record, assertion):
        return WebAuthnVerificationResult(
            False, "Order parameters in approval record do not match WebAuthn assertion bundle."
        )

    raw_nonce = assertion.get("challenge_nonce") or record.get("challenge_nonce")
    challenge_nonce = raw_nonce.strip() if isinstance(raw_nonce, str) and raw_nonce.strip() else ""
    if not challenge_nonce:
        return WebAuthnVerificationResult(
            False,
            "Missing challenge_nonce: nonce-less WebAuthn challenges are rejected (expected sha256(nonce:approval_hash)).",
        )

    record_hash = str(record.get("approval_hash") or "").strip()
    bundle_hash = str(assertion.get("approval_hash") or "").strip()
    if record_hash and bundle_hash and record_hash != bundle_hash:
        return WebAuthnVerificationResult(
            False, "approval_hash mismatch between approval record and WebAuthn assertion."
        )
    approval_hash = record_hash or bundle_hash

    if approval_hash and _has_canonical_approval_record_fields(record):
        try:
            recomputed_hash = compute_approval_hash(record)
        except Exception as exc:
            return WebAuthnVerificationResult(
                False, f"Failed computing canonical approval_hash from order fields: {exc}"
            )
        if recomputed_hash != approval_hash:
            return WebAuthnVerificationResult(
                False,
                "Order parameters in approval record do not match approval_hash (tampered order rejected).",
            )

    valid_challenge_digests: list[bytes] = []
    if approval_hash:
        valid_challenge_digests.append(
            hashlib.sha256(f"{challenge_nonce}:{approval_hash}".encode("utf-8")).digest()
        )
    else:
        order_digest = canonical_order_digest(record)
        valid_challenge_digests.append(
            hashlib.sha256(f"{challenge_nonce}:{order_digest}".encode("utf-8")).digest()
        )
        if _has_canonical_approval_record_fields(record):
            recomputed_approval_hash = compute_approval_hash(record)
            valid_challenge_digests.append(
                hashlib.sha256(f"{challenge_nonce}:{recomputed_approval_hash}".encode("utf-8")).digest()
            )

    matched_challenge_bytes: Optional[bytes] = None
    for digest in valid_challenge_digests:
        if hmac.compare_digest(client_challenge, _b64u_encode(digest)):
            matched_challenge_bytes = digest
            break

    if matched_challenge_bytes is None:
        return WebAuthnVerificationResult(
            False,
            "WebAuthn challenge mismatch: expected base64url(sha256(nonce:approval_hash)).",
        )

    # Construct py_webauthn AuthenticationCredential using normalized raw_id / id pair.
    raw_cred_id = cred_id.encode("utf-8") if cred_id else b"pinned-passkey"
    credential = AuthenticationCredential(
        id=bytes_to_base64url(raw_cred_id),
        raw_id=raw_cred_id,
        response=AuthenticatorAssertionResponse(
            client_data_json=client_data_bytes,
            authenticator_data=auth_data,
            signature=sig_bytes,
        ),
    )

    # Delegate full WebAuthn verification (rpIdHash, UP+UV, type, origin, challenge,
    # monotonic sign_count, and cryptographic signature) to py_webauthn against ONLY
    # locally pinned COSE public keys.
    for key_kind, cose_key_bytes in parsed_cose_keys:
        try:
            verified = webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=matched_challenge_bytes,
                expected_rp_id=rp_id_clean,
                expected_origin=origin_clean,
                credential_public_key=cose_key_bytes,
                credential_current_sign_count=current_sign_count,
                require_user_verification=True,
            )
            return WebAuthnVerificationResult(
                True,
                f"WebAuthn {key_kind} co-signature verified via py_webauthn against locally pinned key.",
                new_sign_count=verified.new_sign_count,
                credential_id=cred_id or None,
                user_verified=verified.user_verified,
            )
        except InvalidAuthenticationResponse as exc:
            err_msg = str(exc)
            if "could not verify authentication signature" in err_msg.lower():
                continue
            return WebAuthnVerificationResult(
                False,
                _format_webauthn_error(
                    err_msg,
                    expected_rp_id=rp_id_clean,
                    expected_origin=origin_clean,
                ),
            )
        except Exception as exc:
            return WebAuthnVerificationResult(
                False,
                f"WebAuthn verification error: {exc}",
            )

    return WebAuthnVerificationResult(
        False,
        "WebAuthn cryptographic signature failed against all locally pinned trusted keys.",
    )
