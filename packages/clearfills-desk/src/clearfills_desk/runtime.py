"""Core runtime & role contracts for ClearFills Desk OS."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from clearfills_firewall import (
    FirewallService,
    PortfolioSnapshot,
    RiskDecision,
    RiskPolicy,
    SignedAttestation,
    TradeProposal,
)

from .enclave_client import RemoteEnclaveFirewallClient, TransportCallable

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


class DeskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    desk_id: str = Field(..., min_length=1, max_length=64)
    desk_name: str = Field(..., min_length=1, max_length=120)
    execution_mode: Literal["paper", "live", "shadow", "enforce"] = "paper"
    venue: str = "ibkr"
    human_confirm_above_usd: float = Field(default=25_000.0, ge=0.0)
    remote_signer_endpoint: str | None = None
    operator_passkey_spki_b64: list[str] = Field(default_factory=list)
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
        result = self.firewall.dispatch_check(attestation=attestation, proposal=proposal)
        return bool(result.allowed)
