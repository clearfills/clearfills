"""ClearFills Universal Pre-Trade Risk Firewall & MCP Server (clearfills.com)."""

from .adapters import from_ai_hedge_fund_signal, from_tradingagents_decision
from .attestation import AttestationAuthority, canonical_order_hash
from .custom_guards import (
    CustomGuardFn,
    DeclarativeGuardRule,
    GuardViolation,
    evaluate_declarative_rule,
)
from .envelopes import (
    EnvelopeEvaluator,
    EnvelopeVerdict,
    RiskProfilePreset,
    StrategyEnvelope,
    compute_envelope_signature_hash,
    list_risk_profiles,
    policy_from_profile,
)
from .killswitch import KillSwitch, KillSwitchState
from .ledger import AuditLedger, GENESIS_HASH
from .mcp_server import handle_jsonrpc_request, run_stdio_server
from .models import (
    AuditEntry,
    DecisionStatus,
    ExecutionReceipt,
    OrderType,
    PortfolioSnapshot,
    Position,
    RiskDecision,
    Side,
    SignedAttestation,
    TradeProposal,
    VenueType,
)
from .policy import RiskPolicy, SleevePolicy, default_allocation_sleeves, evaluate_proposal
from .policy_compiler import (
    BenchmarkReport,
    BenchmarkScenarioResult,
    CompiledPolicyResult,
    ExtractedRule,
    SelfTestCheck,
    compile_natural_language_policy,
    run_safety_benchmark,
)
from .server import FirewallService, create_app

__all__ = [
    "AttestationAuthority",
    "AuditEntry",
    "AuditLedger",
    "BenchmarkReport",
    "BenchmarkScenarioResult",
    "CompiledPolicyResult",
    "CustomGuardFn",
    "DecisionStatus",
    "DeclarativeGuardRule",
    "EnvelopeEvaluator",
    "EnvelopeVerdict",
    "ExecutionReceipt",
    "ExtractedRule",
    "FirewallService",
    "GENESIS_HASH",
    "GuardViolation",
    "KillSwitch",
    "KillSwitchState",
    "OrderType",
    "PortfolioSnapshot",
    "Position",
    "RiskDecision",
    "RiskPolicy",
    "RiskProfilePreset",
    "SelfTestCheck",
    "Side",
    "SignedAttestation",
    "SleevePolicy",
    "StrategyEnvelope",
    "TradeProposal",
    "VenueType",
    "canonical_order_hash",
    "compile_natural_language_policy",
    "compute_envelope_signature_hash",
    "create_app",
    "default_allocation_sleeves",
    "evaluate_declarative_rule",
    "evaluate_proposal",
    "from_ai_hedge_fund_signal",
    "from_tradingagents_decision",
    "handle_jsonrpc_request",
    "list_risk_profiles",
    "policy_from_profile",
    "run_safety_benchmark",
    "run_stdio_server",
]
