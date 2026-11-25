"""FastAPI HTTP service & orchestrator for the ClearFills Pre-Trade Risk Firewall."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from fastapi import FastAPI

from .attestation import AttestationAuthority, canonical_order_hash
from .custom_guards import (
    CustomGuardFn,
    DeclarativeGuardRule,
    GuardViolation,
    evaluate_declarative_rule,
)
from .killswitch import KillSwitch, KillSwitchState
from .ledger import AuditLedger
from .models import DecisionStatus, PortfolioSnapshot, RiskDecision, SignedAttestation, TradeProposal
from .policy import RiskPolicy, evaluate_proposal


class ProposeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal: TradeProposal
    portfolio: PortfolioSnapshot


class DispatchCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attestation: SignedAttestation
    proposal: TradeProposal


class DispatchCheckResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    attestation_id: str
    proposal_id: str
    order_hash: str


class KillSwitchTripRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1)
    actor: str = Field(..., min_length=1)


class KillSwitchResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1)
    approver: str = Field(..., min_length=1)


class AuditVerifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    error: Optional[str] = None
    entry_count: int


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    service: str = "clearfills-risk-firewall"
    powered_by: str = "ClearFills"
    kill_switch_tripped: bool
    audit_chain_valid: bool
    audit_entries: int
    key_id: str


class FirewallService:
    """Cohesive runtime service combining Policy, KillSwitch, AttestationAuthority, and AuditLedger."""

    def __init__(
        self,
        *,
        policy: RiskPolicy,
        kill_switch: KillSwitch,
        authority: AttestationAuthority,
        ledger: AuditLedger,
    ) -> None:
        self.policy = policy
        self.kill_switch = kill_switch
        self.authority = authority
        self.ledger = ledger
        self._custom_guards: dict[str, CustomGuardFn] = {}
        self._declarative_rules: dict[str, DeclarativeGuardRule] = {}

    def register_guard(self, name: str, fn: CustomGuardFn) -> None:
        """Register a deterministic Python custom guard evaluated before Ed25519 signing."""
        cleaned = name.strip()
        if not cleaned:
            raise ValueError("Guard name must be non-empty.")
        self._custom_guards[cleaned] = fn

    def guard(self, name: str):
        """Decorator shorthand for register_guard(name, fn)."""
        def _decorator(fn: CustomGuardFn) -> CustomGuardFn:
            self.register_guard(name, fn)
            return fn
        return _decorator

    def unregister_guard(self, name: str) -> bool:
        return self._custom_guards.pop(name.strip(), None) is not None

    def add_declarative_rule(self, rule: DeclarativeGuardRule) -> None:
        self._declarative_rules[rule.rule_id] = rule

    def remove_declarative_rule(self, rule_id: str) -> bool:
        return self._declarative_rules.pop(rule_id, None) is not None

    def list_custom_guards(self) -> dict[str, list[str]]:
        return {
            "python_guards": sorted(self._custom_guards.keys()),
            "declarative_rules": sorted(self._declarative_rules.keys()),
        }

    @classmethod
    def from_data_dir(
        cls,
        data_dir: str | Path,
        policy: Optional[RiskPolicy] = None,
        policy_path: Optional[str | Path] = None,
        initialize_armed: bool = False,
        ttl_seconds: int = 120,
    ) -> "FirewallService":
        base = Path(data_dir)
        base.mkdir(parents=True, exist_ok=True)

        resolved_policy = policy
        if resolved_policy is None:
            if policy_path is not None and Path(policy_path).exists():
                resolved_policy = RiskPolicy.from_yaml(policy_path)
            else:
                resolved_policy = RiskPolicy()

        ks = KillSwitch(base / "killswitch.json")
        if initialize_armed and not ks.state_path.exists():
            ks.initialize_armed(actor="system", reason="Bootstrap armed state")

        authority = AttestationAuthority.from_pem_file(
            pem_path=base / "authority_ed25519.pem",
            ttl_seconds=ttl_seconds,
            spent_nonces_path=base / "spent_nonces.json",
        )
        ledger = AuditLedger(base / "audit_ledger.jsonl")
        return cls(policy=resolved_policy, kill_switch=ks, authority=authority, ledger=ledger)

    def propose(self, proposal: TradeProposal, portfolio: PortfolioSnapshot) -> RiskDecision:
        """Evaluate proposal, issue Ed25519 attestation if approved, and append to audit ledger."""
        decision = evaluate_proposal(
            proposal=proposal,
            portfolio=portfolio,
            policy=self.policy,
            kill_switch=self.kill_switch,
        )

        # Evaluate extensible declarative rules and Python custom guards (fail closed on error)
        custom_violations: list[GuardViolation] = []
        for rule in self._declarative_rules.values():
            try:
                v = evaluate_declarative_rule(rule, proposal, portfolio)
                if v is not None:
                    custom_violations.append(v)
            except Exception as exc:
                custom_violations.append(
                    GuardViolation(
                        code="CUSTOM_GUARD_ERROR",
                        reason=f"Declarative rule '{rule.rule_id}' raised {type(exc).__name__}: {exc}",
                        guard_name=rule.name,
                    )
                )

        for gname, gfn in self._custom_guards.items():
            try:
                res = gfn(proposal, portfolio)
                if isinstance(res, GuardViolation):
                    custom_violations.append(res)
                elif isinstance(res, list):
                    custom_violations.extend(v for v in res if isinstance(v, GuardViolation))
            except Exception as exc:
                custom_violations.append(
                    GuardViolation(
                        code="CUSTOM_GUARD_ERROR",
                        reason=f"Custom guard '{gname}' raised {type(exc).__name__}: {exc}",
                        guard_name=gname,
                    )
                )

        if custom_violations:
            decision.approved = False
            decision.status = DecisionStatus.VETOED
            for v in custom_violations:
                if v.code not in decision.reason_codes:
                    decision.reason_codes.append(v.code)
                decision.reasons.append(f"[{v.guard_name}] {v.reason}")

        if decision.approved:
            decision.attestation = self.authority.issue(proposal)

        self.ledger.append(
            event_type="PROPOSAL_APPROVED" if decision.approved else "PROPOSAL_VETOED",
            actor=proposal.agent_id,
            payload={
                "decision_id": decision.decision_id,
                "proposal_id": proposal.proposal_id,
                "venue": proposal.venue,
                "symbol": proposal.symbol,
                "side": proposal.side.value,
                "quantity": proposal.quantity,
                "limit_price": proposal.limit_price,
                "stop_price": proposal.stop_price,
                "target_price": proposal.target_price,
                "approved": decision.approved,
                "reason_codes": decision.reason_codes,
                "attestation_id": decision.attestation.attestation_id if decision.attestation else None,
                "order_hash": decision.attestation.order_hash if decision.attestation else canonical_order_hash(proposal),
            },
        )
        return decision

    def dispatch_check(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
    ) -> DispatchCheckResponse:
        """Verify and atomically consume an attestation at the execution boundary."""
        allowed, reason = self.authority.verify_and_consume(attestation=attestation, proposal=proposal)
        computed_hash = canonical_order_hash(proposal)

        self.ledger.append(
            event_type="DISPATCH_ALLOWED" if allowed else "DISPATCH_REJECTED",
            actor=proposal.agent_id,
            payload={
                "attestation_id": attestation.attestation_id,
                "proposal_id": proposal.proposal_id,
                "allowed": allowed,
                "reason": reason,
                "order_hash": computed_hash,
            },
        )
        return DispatchCheckResponse(
            allowed=allowed,
            reason=reason,
            attestation_id=attestation.attestation_id,
            proposal_id=proposal.proposal_id,
            order_hash=computed_hash,
        )

    def trip_kill_switch(self, reason: str, actor: str) -> KillSwitchState:
        state = self.kill_switch.trip(reason=reason, actor=actor)
        self.ledger.append(
            event_type="KILL_SWITCH_TRIPPED",
            actor=actor,
            payload={"reason": reason, "tripped": state.tripped},
        )
        return state

    def reset_kill_switch(self, reason: str, approver: str) -> KillSwitchState:
        state = self.kill_switch.reset(reason=reason, approver=approver)
        self.ledger.append(
            event_type="KILL_SWITCH_RESET",
            actor=approver,
            payload={"reason": reason, "tripped": state.tripped},
        )
        return state

    def verify_audit(self) -> AuditVerifyResponse:
        valid, err, count = self.ledger.verify_chain()
        return AuditVerifyResponse(valid=valid, error=err, entry_count=count)


def create_app(service: Optional[FirewallService] = None) -> "FastAPI":
    """Create the FastAPI application wired to a `FirewallService` instance."""
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise ImportError(
            "FastAPI is required for the HTTP server. Install with: pip install 'clearfills[server]'"
        ) from exc

    if service is None:
        data_dir = os.environ.get("CLEARFILLS_DATA_DIR", "./.clearfills_data")
        policy_path = os.environ.get("CLEARFILLS_POLICY_YAML")
        init_armed = os.environ.get("CLEARFILLS_INIT_ARMED", "0") == "1"
        service = FirewallService.from_data_dir(
            data_dir=data_dir,
            policy_path=policy_path,
            initialize_armed=init_armed,
        )

    app = FastAPI(
        title="ClearFills Pre-Trade Risk Firewall",
        description="Universal Pre-Trade Risk Firewall & Attestation Authority (clearfills.com)",
        version="0.1.0",
    )
    app.state.firewall = service

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        ks = service.kill_switch.status()
        audit = service.verify_audit()
        return HealthResponse(
            status="ok" if audit.valid else "degraded",
            kill_switch_tripped=ks.tripped,
            audit_chain_valid=audit.valid,
            audit_entries=audit.entry_count,
            key_id=service.authority.key_id,
        )

    @app.post("/v1/propose", response_model=RiskDecision)
    def propose_trade(req: ProposeRequest) -> RiskDecision:
        return service.propose(proposal=req.proposal, portfolio=req.portfolio)

    @app.post("/v1/dispatch-check", response_model=DispatchCheckResponse)
    def dispatch_check(req: DispatchCheckRequest) -> JSONResponse:
        result = service.dispatch_check(attestation=req.attestation, proposal=req.proposal)
        status_code = 200 if result.allowed else 403
        return JSONResponse(status_code=status_code, content=result.model_dump(mode="json"))

    @app.get("/v1/killswitch/status", response_model=KillSwitchState)
    def killswitch_status() -> KillSwitchState:
        return service.kill_switch.status()

    @app.post("/v1/killswitch/trip", response_model=KillSwitchState)
    def killswitch_trip(req: KillSwitchTripRequest) -> KillSwitchState:
        try:
            return service.trip_kill_switch(reason=req.reason, actor=req.actor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/killswitch/reset", response_model=KillSwitchState)
    def killswitch_reset(req: KillSwitchResetRequest) -> KillSwitchState:
        try:
            return service.reset_kill_switch(reason=req.reason, approver=req.approver)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/audit/verify", response_model=AuditVerifyResponse)
    def audit_verify() -> AuditVerifyResponse:
        return service.verify_audit()

    return app


def main() -> None:
    """Run the FastAPI risk firewall server via uvicorn."""
    try:
        import uvicorn
    except ImportError as exc:
        raise ImportError(
            "uvicorn is required for the HTTP server. Install with: pip install 'clearfills[server]'"
        ) from exc

    host = os.environ.get("CLEARFILLS_HOST", "127.0.0.1")
    port = int(os.environ.get("CLEARFILLS_PORT", "8080"))
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    main()
