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
from .server import FirewallService, create_app

__all__ = [
    "AttestationAuthority",
    "AuditEntry",
    "AuditLedger",
    "DecisionStatus",
    "ExecutionReceipt",
    "FirewallService",
    "GENESIS_HASH",
    "KillSwitch",
    "KillSwitchState",
    "OrderType",
    "PortfolioSnapshot",
    "Position",
    "RiskDecision",
    "RiskPolicy",
    "Side",
    "SignedAttestation",
    "SleevePolicy",
    "TradeProposal",
    "VenueType",
    "canonical_order_hash",
    "create_app",
    "default_allocation_sleeves",
    "evaluate_proposal",
    "from_ai_hedge_fund_signal",
    "from_tradingagents_decision",
    "handle_jsonrpc_request",
    "run_stdio_server",
]
