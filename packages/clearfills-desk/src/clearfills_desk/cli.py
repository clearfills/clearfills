"""CLI for ClearFills Desk OS (paper & two-key live IBKR validation + firewall checks)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from clearfills_firewall import OrderType, PortfolioSnapshot, Side, TradeProposal

from .ibkr import LiveExecutionSafetyError, validate_ibkr_connection
from .runtime import DeskConfig, DeskRuntime
from .telemetry import sanitize_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="clearfills-desk",
        description="ClearFills Desk OS CLI — validate Paper/Live IBKR configs and run pre-trade checks.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate", help="Validate DeskConfig YAML and IBKR fail-closed safety guards.")
    p_val.add_argument("--config", required=True, type=Path, help="Path to desk_rules YAML file.")

    p_chk = sub.add_parser("check-order", help="Evaluate a trade proposal against the desk's RiskPolicy.")
    p_chk.add_argument("--config", required=True, type=Path)
    p_chk.add_argument("--state-dir", default=Path(".clearfills_state"), type=Path)
    p_chk.add_argument("--symbol", required=True)
    p_chk.add_argument("--side", choices=["BUY", "SELL"], default="BUY")
    p_chk.add_argument("--qty", required=True, type=float)
    p_chk.add_argument("--limit", required=True, type=float)
    p_chk.add_argument("--stop", type=float, default=None)
    p_chk.add_argument("--nav", type=float, default=100_000.0)
    p_chk.add_argument("--session-entries", type=int, default=0)

    args = parser.parse_args(argv)
    cfg = DeskConfig.from_yaml(args.config)

    if args.command == "validate":
        mode = "live" if cfg.execution_mode == "live" else "paper"
        try:
            validate_ibkr_connection(cfg.ibkr, mode)
        except LiveExecutionSafetyError as exc:
            print(json.dumps({"valid": False, "mode": mode, "error": sanitize_text(str(exc))}))
            return 2
        summary = {
            "valid": True,
            "desk_id": cfg.desk_id,
            "execution_mode": cfg.execution_mode,
            "venue": cfg.venue,
            "ibkr_host": cfg.ibkr.host,
            "ibkr_port": cfg.ibkr.port,
            "account_configured": bool(cfg.ibkr.account_id),
            "allow_live": cfg.ibkr.allow_live,
            "max_total_heat_pct": cfg.risk.max_total_heat_pct,
            "max_entries_per_session": cfg.risk.max_entries_per_session,
        }
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "check-order":
        rt = DeskRuntime(config=cfg, state_dir=args.state_dir)
        proposal = TradeProposal(
            agent_id="cli",
            venue=cfg.venue,
            symbol=args.symbol,
            side=Side(args.side),
            order_type=OrderType.LIMIT,
            quantity=args.qty,
            limit_price=args.limit,
            stop_price=args.stop,
        )
        portfolio = PortfolioSnapshot(
            nav_usd=args.nav,
            cash_usd=args.nav,
            session_entries=args.session_entries,
        )
        decision = rt.evaluate_proposal(proposal, portfolio)
        out = {
            "approved": decision.approved,
            "status": decision.status.value,
            "reason_codes": decision.reason_codes,
            "attestation_id": decision.attestation.attestation_id if decision.attestation else None,
        }
        print(json.dumps(out, indent=2))
        return 0 if decision.approved else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
