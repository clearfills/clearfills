"""Core runtime & role contracts for ClearFills Desk OS."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator

from clearfills_firewall import (
    FirewallService,
    PortfolioSnapshot,
    RiskDecision,
    RiskPolicy,
    SignedAttestation,
    TradeProposal,
    canonical_order_hash,
)

from .enclave_client import RemoteEnclaveFirewallClient, TransportCallable
from .webauthn_verifier import DEFAULT_WEBAUTHN_ORIGIN, DEFAULT_WEBAUTHN_RP_ID

DESK_ROLES: dict[str, str] = {
    "researcher": "Gathers filings, catalysts, and market data (read-only, zero broker keys).",
    "strategist": "Proposes structured TradeProposal intents with entry, stop-loss, and citations.",
    "risk_officer": "Delegates deterministically to clearfills-firewall RiskPolicy and Ed25519 attestations.",
    "trader": "Verifies single-use Ed25519 attestation via dispatch_check() before routing to venue.",
    "chief_of_staff": "Relays operator desk decisions and monitors heartbeats and alerts.",
    "auditor": "Verifies SHA-256 audit ledger and publishes sanitized Arena heartbeats and Strategy Receipts.",
}


class IBKRConnectionConfig(BaseModel):
    """IBKR TWS / IB Gateway connection settings with fail-closed paper/live separation."""

    model_config = ConfigDict(extra="forbid")

    host: str = "127.0.0.1"
    port: int = 4002  # 4002/7497 = Paper, 4001/7496 = Live
    client_id: int = 17
    account_id: str | None = None
    allow_live: bool = False
    allow_tailnet_relay: bool = False


class SplitKeyTicketVerifier:
    """Verify-only Ed25519 verifier for Cloud-issued policy tickets (holds NO private key)."""

    def __init__(
        self,
        authority_public_key_pem: str,
        *,
        spent_nonces_path: Optional[str | Path] = None,
    ) -> None:
        cleaned = (authority_public_key_pem or "").strip()
        if not cleaned or "PRIVATE KEY" in cleaned:
            raise ValueError(
                "authority_public_key_pem must be a verify-only Ed25519 public key PEM (never a private key)."
            )
        try:
            pub = serialization.load_pem_public_key(cleaned.encode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Invalid Ed25519 authority_public_key_pem: {exc}") from exc
        if not isinstance(pub, Ed25519PublicKey):
            raise ValueError("authority_public_key_pem must be an Ed25519 public key.")

        self._public_key: Ed25519PublicKey = pub
        pub_raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._key_id = f"ed25519_{hashlib.sha256(pub_raw).hexdigest()[:16]}"
        self._lock = threading.Lock()
        self._spent_nonces_path = Path(spent_nonces_path) if spent_nonces_path else None
        self._spent_nonces: set[str] = self._load_spent_nonces()

    @property
    def key_id(self) -> str:
        return self._key_id

    @staticmethod
    def _canonical_attestation_bytes(attestation: SignedAttestation) -> bytes:
        message = {
            "attestation_id": attestation.attestation_id,
            "nonce": attestation.nonce,
            "proposal_id": attestation.proposal_id,
            "agent_id": attestation.agent_id,
            "order_hash": attestation.order_hash,
            "issued_at": attestation.issued_at.astimezone(timezone.utc).isoformat(),
            "expires_at": attestation.expires_at.astimezone(timezone.utc).isoformat(),
            "key_id": attestation.key_id,
        }
        return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _check_static(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
        now: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        check_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if attestation.key_id != self._key_id:
            return False, "UNKNOWN_KEY_ID"

        msg = self._canonical_attestation_bytes(attestation)
        try:
            raw_sig = base64.b64decode(attestation.signature_b64.encode("ascii"), validate=True)
            self._public_key.verify(raw_sig, msg)
        except (InvalidSignature, ValueError):
            return False, "INVALID_SIGNATURE"

        expected_hash = canonical_order_hash(proposal)
        if attestation.order_hash != expected_hash:
            return False, "ORDER_HASH_MISMATCH"

        if check_time > attestation.expires_at.astimezone(timezone.utc):
            return False, "ATTESTATION_EXPIRED"
        if check_time < attestation.issued_at.astimezone(timezone.utc) - timedelta(seconds=5):
            return False, "ATTESTATION_NOT_YET_VALID"

        return True, "OK"

    def verify(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
        now: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        """Read-only verification of a Cloud-issued Ed25519 policy ticket (does not consume nonce)."""
        ok, code = self._check_static(attestation, proposal, now=now)
        if not ok:
            return False, code
        with self._lock:
            if self._spent_nonces_path is not None:
                self._spent_nonces |= self._load_spent_nonces()
            if attestation.nonce in self._spent_nonces:
                return False, "ATTESTATION_REPLAY_DETECTED"
        return True, "OK"

    def verify_and_consume(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
        now: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        """Verify Ed25519 signature, order-hash binding, TTL, and atomically consume nonce."""
        ok, code = self._check_static(attestation, proposal, now=now)
        if not ok:
            return False, code
        with self._lock:
            if self._spent_nonces_path is not None:
                self._spent_nonces |= self._load_spent_nonces()
            if attestation.nonce in self._spent_nonces:
                return False, "ATTESTATION_REPLAY_DETECTED"
            self._spent_nonces.add(attestation.nonce)
            self._persist_spent_nonces()
        return True, "OK"

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
            prefix=".ticket_nonces_",
            suffix=".tmp",
            dir=str(self._spent_nonces_path.parent),
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


class DeskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    desk_id: str = Field(..., min_length=1, max_length=64)
    desk_name: str = Field(..., min_length=1, max_length=120)
    execution_mode: Literal["paper", "live", "shadow", "enforce"] = "paper"
    venue: str = "ibkr"
    human_confirm_above_usd: float = Field(default=25_000.0, ge=0.0)
    remote_signer_endpoint: str | None = None
    authority_public_key_pem: str | None = None
    operator_passkey_spki_b64: list[str] = Field(default_factory=list)
    trusted_credential_ids: list[str] = Field(default_factory=list)
    webauthn_rp_id: str = DEFAULT_WEBAUTHN_RP_ID
    webauthn_origin: str = DEFAULT_WEBAUTHN_ORIGIN
    ibkr: IBKRConnectionConfig = Field(default_factory=IBKRConnectionConfig)
    risk: RiskPolicy = Field(default_factory=RiskPolicy)

    @field_validator("remote_signer_endpoint")
    @classmethod
    def _validate_remote_signer_endpoint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if not cleaned.startswith(("unix://", "http://", "https://")):
            raise ValueError(
                "remote_signer_endpoint must start with 'unix://', 'http://', or 'https://'."
            )
        return cleaned

    @field_validator("operator_passkey_spki_b64")
    @classmethod
    def _normalize_operator_passkeys(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]

    @classmethod
    def from_yaml(cls, path: str | Path) -> "DeskConfig":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("DeskConfig YAML must be a top-level mapping")
        return cls.model_validate(raw)


class DeskRuntime:
    """Thin multi-agent desk orchestrator delegating all risk enforcement to clearfills-firewall."""

    def __init__(
        self,
        config: DeskConfig,
        state_dir: str | Path,
        *,
        enclave_client: RemoteEnclaveFirewallClient | None = None,
        enclave_transport: TransportCallable | None = None,
    ) -> None:
        self.config = config
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.enclave_client: RemoteEnclaveFirewallClient | None = None
        self.firewall: FirewallService | RemoteEnclaveFirewallClient
        self.ticket_verifier: SplitKeyTicketVerifier | None = None

        if config.authority_public_key_pem:
            self.set_authority_public_key(config.authority_public_key_pem)

        if enclave_client is not None:
            self.enclave_client = enclave_client
            self.firewall = enclave_client
        elif config.remote_signer_endpoint:
            self.enclave_client = RemoteEnclaveFirewallClient(
                config.remote_signer_endpoint,
                transport=enclave_transport,
            )
            self.firewall = self.enclave_client
        else:
            self.firewall = FirewallService.from_data_dir(
                data_dir=self.state_dir / "firewall",
                policy=config.risk,
                initialize_armed=True,
                ttl_seconds=120,
            )

    def set_authority_public_key(self, authority_public_key_pem: str) -> SplitKeyTicketVerifier:
        """Configure verify-only Ed25519 split-key policy ticket verification."""
        self.ticket_verifier = SplitKeyTicketVerifier(
            authority_public_key_pem,
            spent_nonces_path=self.state_dir / "firewall" / "spent_ticket_nonces.json",
        )
        return self.ticket_verifier

    def evaluate_proposal(
        self,
        proposal: TradeProposal,
        portfolio: PortfolioSnapshot,
    ) -> RiskDecision:
        """Run deterministic pre-trade risk evaluation (Risk Officer step)."""
        return self.firewall.propose(proposal=proposal, portfolio=portfolio)

    def verify_dispatch(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
    ) -> bool:
        """Verify single-use Ed25519 attestation prior to broker dispatch (Trader step)."""
        if self.ticket_verifier is not None:
            ks = getattr(self.firewall, "kill_switch", None)
            if ks is not None and ks.status().tripped:
                return False
            ok, _ = self.ticket_verifier.verify_and_consume(
                attestation=attestation,
                proposal=proposal,
            )
            return ok
        result = self.firewall.dispatch_check(attestation=attestation, proposal=proposal)
        return bool(result.allowed)
