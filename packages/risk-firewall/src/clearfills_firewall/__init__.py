"""ClearFills Universal Pre-Trade Risk Firewall & MCP Server (clearfills.com)."""

from .adapters import from_ai_hedge_fund_signal, from_tradingagents_decision
from .attestation import AttestationAuthority, canonical_order_hash
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
    "DecisionStatus",
    "ExecutionReceipt",
    "ExtractedRule",
    "FirewallService",
    "GENESIS_HASH",
    "KillSwitch",
    "KillSwitchState",
    "OrderType",
    "PortfolioSnapshot",
    "Position",
    "RiskDecision",
    "RiskPolicy",
    "SelfTestCheck",
    "Side",
    "SignedAttestation",
    "SleevePolicy",
    "TradeProposal",
    "VenueType",
    "canonical_order_hash",
    "compile_natural_language_policy",
    "create_app",
    "default_allocation_sleeves",
    "evaluate_proposal",
    "from_ai_hedge_fund_signal",
    "from_tradingagents_decision",
    "handle_jsonrpc_request",
    "run_safety_benchmark",
    "run_stdio_server",
]
