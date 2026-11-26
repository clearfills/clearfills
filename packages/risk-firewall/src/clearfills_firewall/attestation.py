"""Ed25519 single-use, exact-order-hash bound attestation authority & split-key verifier.

Uses RFC 8785 (JCS) canonical JSON serialization for all order-leg hashing and
attestation signing payloads. Separates signing (`AttestationAuthority`, private key)
from verification (`AttestationVerifier`, public key only) so execution gateways
never need access to the signing key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import tempfile
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

from ._locks import file_lock
from .canonical import canonical_json_bytes
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
    """Compute canonical SHA-256 hex digest over immutable order legs using RFC 8785 JCS."""
    payload_bytes = canonical_json_bytes(canonical_order_legs(proposal))
    return hashlib.sha256(payload_bytes).hexdigest()


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
    return canonical_json_bytes(message)


def _compute_key_id(public_key: Ed25519PublicKey) -> str:
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519_{hashlib.sha256(pub_bytes).hexdigest()[:16]}"


def _load_public_key(public_key_pem: bytes | str | Ed25519PublicKey) -> Ed25519PublicKey:
    if isinstance(public_key_pem, Ed25519PublicKey):
        return public_key_pem
    raw = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    loaded = serialization.load_pem_public_key(raw)
    if not isinstance(loaded, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519 public key, got {type(loaded).__name__}")
    return loaded


def _load_private_key(private_key_pem: bytes | str | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(private_key_pem, Ed25519PrivateKey):
        return private_key_pem
    raw = private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
    loaded = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519 private key, got {type(loaded).__name__}")
    return loaded


class AttestationVerifier:
    """Public-key-only verifier for single-use, TTL-enforced Ed25519 trade attestations.

    Holds ONLY the Ed25519 public key and cannot sign or mint attestation tickets.
    Suitable for deployment inside execution gateways, brokers, and external verifiers.
    """

    def __init__(
        self,
        public_key_pem: bytes | str | Ed25519PublicKey,
        *,
        spent_nonces_path: Optional[str | Path] = None,
    ) -> None:
        self._public_key: Ed25519PublicKey = _load_public_key(public_key_pem)
        self._key_id = _compute_key_id(self._public_key)
        self._lock = threading.Lock()
        self._spent_nonces_path = Path(spent_nonces_path) if spent_nonces_path else None
        self._spent_nonces: set[str] = self._load_spent_nonces()

    @classmethod
    def from_pem_file(
        cls,
        pem_path: str | Path,
        spent_nonces_path: Optional[str | Path] = None,
    ) -> "AttestationVerifier":
        """Load an Ed25519 public key from a local PEM file."""
        return cls(Path(pem_path).read_bytes(), spent_nonces_path=spent_nonces_path)

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def verify(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
        now: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        """Verify Ed25519 signature, exact RFC 8785 order hash, and TTL without consuming nonce."""
        check_time = (now or utc_now()).astimezone(timezone.utc)

        # 1. Key ID check
        if attestation.key_id != self._key_id:
            return False, "UNKNOWN_KEY_ID"

        # 2. Verify Ed25519 signature over RFC 8785 canonical attestation payload
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

        return True, "OK"

    def verify_and_consume(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
        now: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        """Verify signature, exact order hash, TTL, and atomically consume the single-use nonce."""
        ok, reason = self.verify(attestation=attestation, proposal=proposal, now=now)
        if not ok:
            return False, reason

        # 5. Atomic single-use nonce check & consumption (cross-process locked)
        with self._lock, file_lock(self._spent_nonces_path):
            if self._spent_nonces_path is not None:
                self._spent_nonces |= self._load_spent_nonces()
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
        payload = json.dumps(sorted(self._spent_nonces))
        fd, tmp_name = tempfile.mkstemp(
            prefix=".nonces_", suffix=".tmp", dir=str(self._spent_nonces_path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self._spent_nonces_path)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise


class AttestationAuthority:
    """Issues (and optionally verifies) single-use, TTL-enforced Ed25519 trade attestations."""

    def __init__(
        self,
        private_key: Optional[Ed25519PrivateKey | bytes | str] = None,
        ttl_seconds: int = 120,
        spent_nonces_path: Optional[str | Path] = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._private_key: Ed25519PrivateKey = (
            _load_private_key(private_key) if private_key is not None else Ed25519PrivateKey.generate()
        )
        self._public_key: Ed25519PublicKey = self._private_key.public_key()
        self._ttl_seconds = ttl_seconds
        self._verifier = AttestationVerifier(
            self._public_key,
            spent_nonces_path=spent_nonces_path,
        )
        self._key_id = self._verifier.key_id

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
            key = _load_private_key(path.read_bytes())
            return cls(private_key=key, ttl_seconds=ttl_seconds, spent_nonces_path=spent_nonces_path)

        key = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        pem_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Create atomically with 0600 permissions so the private key is never world/group-readable
        with file_lock(path):
            if not path.exists():
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(fd, pem_bytes)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.chmod(path, 0o600)
            else:
                key = _load_private_key(path.read_bytes())
        return cls(private_key=key, ttl_seconds=ttl_seconds, spent_nonces_path=spent_nonces_path)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    @property
    def signing_key(self) -> Ed25519PrivateKey:
        """Return the underlying Ed25519 private key for internal signing (e.g. AuditLedger)."""
        return self._private_key

    def public_key_pem(self) -> str:
        return self._verifier.public_key_pem()

    def verifier(self, spent_nonces_path: Optional[str | Path] = None) -> AttestationVerifier:
        """Create a split-key public-only `AttestationVerifier` that cannot sign tickets."""
        return AttestationVerifier(
            self.public_key_pem(),
            spent_nonces_path=spent_nonces_path,
        )

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
        """Verify Ed25519 signature, exact order hash, TTL, and single-use nonce."""
        return self._verifier.verify_and_consume(
            attestation=attestation,
            proposal=proposal,
            now=now,
        )

    def dispatch_check(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
        now: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        """Alias for verify_and_consume() used at the execution gateway boundary."""
        return self.verify_and_consume(attestation=attestation, proposal=proposal, now=now)
