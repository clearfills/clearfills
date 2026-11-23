"""Ed25519 single-use, exact-order-hash bound attestation authority."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .models import SignedAttestation, TradeProposal, utc_now


def _normalize_float(val: Optional[float]) -> Optional[str]:
    if val is None:
        return None
    # Deterministic decimal representation without floating-point noise
    return f"{val:.8f}"


def canonical_order_legs(proposal: TradeProposal) -> dict[str, Any]:
    """Extract the exact immutable order legs bound by an attestation."""
    return {
        "proposal_id": proposal.proposal_id,
        "agent_id": proposal.agent_id,
        "venue": proposal.venue.strip().lower(),
        "venue_type": proposal.venue_type.value,
        "symbol": proposal.symbol.strip().upper(),
        "side": proposal.side.value,
        "order_type": proposal.order_type.value,
        "quantity": _normalize_float(proposal.quantity),
        "limit_price": _normalize_float(proposal.limit_price),
        "stop_price": _normalize_float(proposal.stop_price),
        "target_price": _normalize_float(proposal.target_price),
    }


def canonical_order_hash(proposal: TradeProposal) -> str:
    """Compute canonical SHA-256 hex digest over immutable order legs."""
    payload = json.dumps(canonical_order_legs(proposal), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_attestation_bytes(
    *,
    attestation_id: str,
    nonce: str,
    proposal_id: str,
    agent_id: str,
    order_hash: str,
    issued_at: datetime,
    expires_at: datetime,
    key_id: str,
) -> bytes:
    message = {
        "attestation_id": attestation_id,
        "nonce": nonce,
        "proposal_id": proposal_id,
        "agent_id": agent_id,
        "order_hash": order_hash,
        "issued_at": issued_at.astimezone(timezone.utc).isoformat(),
        "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
        "key_id": key_id,
    }
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AttestationAuthority:
    """Issues and verifies single-use, TTL-enforced Ed25519 trade attestations."""

    def __init__(
        self,
        private_key: Optional[Ed25519PrivateKey] = None,
        ttl_seconds: int = 120,
        spent_nonces_path: Optional[str | Path] = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key: Ed25519PublicKey = self._private_key.public_key()
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._spent_nonces_path = Path(spent_nonces_path) if spent_nonces_path else None
        self._spent_nonces: set[str] = self._load_spent_nonces()

        pub_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._key_id = f"ed25519_{hashlib.sha256(pub_bytes).hexdigest()[:16]}"

    @classmethod
    def from_pem_file(
        cls,
        pem_path: str | Path,
        ttl_seconds: int = 120,
        spent_nonces_path: Optional[str | Path] = None,
    ) -> "AttestationAuthority":
        """Load an Ed25519 private key from a local PEM file (or generate if absent)."""
        path = Path(pem_path)
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise TypeError(f"Expected Ed25519 private key in {path}")
            return cls(private_key=key, ttl_seconds=ttl_seconds, spent_nonces_path=spent_nonces_path)

        key = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        pem_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(pem_bytes)
        return cls(private_key=key, ttl_seconds=ttl_seconds, spent_nonces_path=spent_nonces_path)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def issue(
        self,
        proposal: TradeProposal,
        now: Optional[datetime] = None,
        ttl_seconds: Optional[int] = None,
    ) -> SignedAttestation:
        """Issue a fresh single-use Ed25519 attestation bound to exact order legs."""
        issued_at = (now or utc_now()).astimezone(timezone.utc)
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl_seconds
        expires_at = issued_at + timedelta(seconds=ttl)
        order_hash = canonical_order_hash(proposal)
        nonce = secrets.token_hex(16)
        attestation_id = f"att_{secrets.token_hex(8)}"

        msg = _canonical_attestation_bytes(
            attestation_id=attestation_id,
            nonce=nonce,
            proposal_id=proposal.proposal_id,
            agent_id=proposal.agent_id,
            order_hash=order_hash,
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=self._key_id,
        )
        sig = self._private_key.sign(msg)
        sig_b64 = base64.b64encode(sig).decode("ascii")

        return SignedAttestation(
            attestation_id=attestation_id,
            nonce=nonce,
            proposal_id=proposal.proposal_id,
            agent_id=proposal.agent_id,
            order_hash=order_hash,
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=self._key_id,
            signature_b64=sig_b64,
        )

    def verify_and_consume(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
        now: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        """Verify Ed25519 signature, exact order hash, TTL, and single-use nonce.

        Consumes the nonce atomically on first valid dispatch so replays are impossible.
        """
        check_time = (now or utc_now()).astimezone(timezone.utc)

        # 1. Key ID check
        if attestation.key_id != self._key_id:
            return False, "UNKNOWN_KEY_ID"

        # 2. Verify Ed25519 signature over canonical attestation payload
        msg = _canonical_attestation_bytes(
            attestation_id=attestation.attestation_id,
            nonce=attestation.nonce,
            proposal_id=attestation.proposal_id,
            agent_id=attestation.agent_id,
            order_hash=attestation.order_hash,
            issued_at=attestation.issued_at,
            expires_at=attestation.expires_at,
            key_id=attestation.key_id,
        )
        try:
            raw_sig = base64.b64decode(attestation.signature_b64.encode("ascii"), validate=True)
            self._public_key.verify(raw_sig, msg)
        except (InvalidSignature, ValueError):
            return False, "INVALID_SIGNATURE"

        # 3. Verify exact order-leg hash binding (detects any post-attestation tampering)
        expected_hash = canonical_order_hash(proposal)
        if attestation.order_hash != expected_hash:
            return False, "ORDER_HASH_MISMATCH"

        # 4. Enforce TTL
        if check_time > attestation.expires_at.astimezone(timezone.utc):
            return False, "ATTESTATION_EXPIRED"
        if check_time < attestation.issued_at.astimezone(timezone.utc) - timedelta(seconds=5):
            return False, "ATTESTATION_NOT_YET_VALID"

        # 5. Atomic single-use nonce check & consumption (prevents replay attacks)
        with self._lock:
            if attestation.nonce in self._spent_nonces:
                return False, "ATTESTATION_REPLAY_DETECTED"
            self._spent_nonces.add(attestation.nonce)
            self._persist_spent_nonces()

        return True, "OK"

    def dispatch_check(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
        now: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        """Alias for verify_and_consume() used at the execution gateway boundary."""
        return self.verify_and_consume(attestation=attestation, proposal=proposal, now=now)

    def _load_spent_nonces(self) -> set[str]:
        if self._spent_nonces_path is None or not self._spent_nonces_path.exists():
            return set()
        try:
            data = json.loads(self._spent_nonces_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return {str(x) for x in data}
        except (OSError, json.JSONDecodeError):
            pass
        return set()

    def _persist_spent_nonces(self) -> None:
        if self._spent_nonces_path is None:
            return
        self._spent_nonces_path.parent.mkdir(parents=True, exist_ok=True)
        self._spent_nonces_path.write_text(
            json.dumps(sorted(self._spent_nonces)),
            encoding="utf-8",
        )
