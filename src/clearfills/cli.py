"""Unified CLI for ClearFills (`clearfills init|doctor|mcp|watch|sync|validate|redteam|serve`)."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from clearfills import (
    FirewallService,
    OrderType,
    PortfolioSnapshot,
    RiskPolicy,
    Side,
    TradeProposal,
    __version__,
)

DEFAULT_API_URL = "https://clearfills-api.fly.dev"
DEFAULT_CHALLENGE_MCP_URL = "https://clearfills-api.fly.dev/mcp/challenge"
DEFAULT_CONFIG_FILENAME = ".clearfills.yaml"


def _use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _fmt_status(status: str) -> str:
    tag = status.upper()
    if not _use_color():
        return f"[{tag:4s}]"
    colors = {
        "OK": "\033[32m",
        "PASS": "\033[32m",
        "WARN": "\033[33m",
        "FAIL": "\033[31m",
    }
    reset = "\033[0m"
    color = colors.get(tag, "")
    return f"{color}[{tag:4s}]{reset}"


def _discover_config(explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        return explicit
    env_path = os.environ.get("CLEARFILLS_DESK_CONFIG", "").strip()
    if env_path:
        return Path(env_path)
    default_path = Path(DEFAULT_CONFIG_FILENAME)
    if default_path.exists():
        return default_path
    return None


def _render_init_yaml(*, mode: str, host: str, port: int) -> str:
    is_live = mode == "live"
    desk_id = f"clearfills-desk-{mode}"
    desk_name = f"ClearFills Desk ({'Live' if is_live else 'Paper'})"
    allow_live_str = "true" if is_live else "false"
    live_note = (
        "# WARNING: Live mode also requires CLEARFILLS_ALLOW_LIVE=1 in your shell environment.\n"
        if is_live
        else "# Safe paper default: live execution is fail-closed (allow_live: false).\n"
    )
    return (
        f"# ClearFills Desk Configuration (https://clearfills.com/docs)\n"
        f"{live_note}"
        f"desk_id: {desk_id}\n"
        f"desk_name: {desk_name}\n"
        f"execution_mode: {mode}\n"
        f"venue: ibkr\n"
        f"human_confirm_above_usd: 25000.0\n"
        f"\n"
        f"ibkr:\n"
        f"  host: {host}\n"
        f"  port: {port}  # 4002/7497 = Paper, 4001/7496 = Live\n"
        f"  client_id: 17\n"
        f"  # account_id: DU0000000  # Optional: pin to a specific paper (DU*) or live (U*) account\n"
        f"  allow_live: {allow_live_str}\n"
        f"  allow_tailnet_relay: false\n"
        f"\n"
        f"risk:\n"
        f"  policy_version: \"1.0.0\"\n"
        f"  # Strict active-trading defaults (1% risk cap + mandatory stop-loss)\n"
        f"  max_risk_per_trade_pct: 1.0\n"
        f"  max_open_positions: 10\n"
        f"  max_total_heat_pct: 8.0\n"
        f"  max_daily_loss_pct: 2.0\n"
        f"  require_stop_loss: true\n"
        f"  max_order_notional_usd: 50000.0\n"
        f"  allow_shorting: false\n"
        f"  allowed_venues:\n"
        f"    - ibkr\n"
        f"    - alpaca\n"
        f"    - paper\n"
        f"  sleeves:\n"
        f"    cash_equivalent:\n"
        f"      symbols: [SGOV, BIL, CBIL, SHV, USFR, TFLO]\n"
        f"      require_stop_loss: false\n"
        f"      max_order_notional_usd: 500000.0\n"
        f"      exempt_session_entry_cap: true\n"
        f"      exempt_last_session_of_week: true\n"
        f"      exempt_session_cutoff: true\n"
        f"    core_index:\n"
        f"      symbols: [VT, VTI, SPY, VOO, QQQ, VEQT]\n"
        f"      require_stop_loss: false\n"
        f"      max_order_notional_usd: 500000.0\n"
        f"      exempt_session_entry_cap: true\n"
        f"      exempt_last_session_of_week: true\n"
        f"      exempt_session_cutoff: true\n"
    )


def _cmd_init(args: argparse.Namespace) -> int:
    output: Path = args.output
    if output.exists() and not args.force:
        print(
            f"Refusing to overwrite existing {output}. Pass --force to overwrite.",
            file=sys.stderr,
        )
        return 1

    port = args.port if args.port is not None else (4001 if args.mode == "live" else 4002)
    content = _render_init_yaml(mode=args.mode, host=args.host, port=port)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")

    print(f"Wrote {output} ({args.mode} mode, IBKR {args.host}:{port})")
    print()
    print("Next steps:")
    print(f"  1. clearfills doctor --config {output}")
    print(f"  2. clearfills watch --config {output} --dry-run")
    print("  3. clearfills mcp")
    if args.mode == "live":
        print("  Note: Live IBKR execution also requires CLEARFILLS_ALLOW_LIVE=1 in your shell.")
    return 0


def _check_tcp(host: str, port: int, timeout: float = 1.5) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"Reachable at {host}:{port}"
    except OSError as exc:
        return False, f"Not reachable at {host}:{port} ({exc.strerror or type(exc).__name__})"


def _cmd_doctor(args: argparse.Namespace) -> int:
    from clearfills_desk.ibkr import LiveExecutionSafetyError, validate_ibkr_connection
    from clearfills_desk.runtime import DeskConfig
    from clearfills_desk.telemetry import sanitize_text

    checks: list[dict[str, str]] = []

    # 1. Python & clearfills version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(
        {
            "name": "runtime",
            "status": "ok",
            "detail": f"clearfills {__version__} on Python {py_ver}",
        }
    )

    # 2. Config file found & valid
    cfg_path = _discover_config(args.config)
    ibkr_host = "127.0.0.1"
    ibkr_port = 4002
    if cfg_path is None or not cfg_path.exists():
        checks.append(
            {
                "name": "config",
                "status": "warn",
                "detail": "No .clearfills.yaml found (run `clearfills init` to create one)",
            }
        )
    else:
        try:
            cfg = DeskConfig.from_yaml(cfg_path)
            ibkr_host = cfg.ibkr.host
            ibkr_port = cfg.ibkr.port
            mode = "live" if cfg.execution_mode == "live" else "paper"
            validate_ibkr_connection(cfg.ibkr, mode)
            checks.append(
                {
                    "name": "config",
                    "status": "ok",
                    "detail": f"{cfg_path} valid ({mode} mode, {ibkr_host}:{ibkr_port})",
                }
            )
        except LiveExecutionSafetyError as exc:
            checks.append(
                {
                    "name": "config",
                    "status": "fail",
                    "detail": f"{cfg_path}: {sanitize_text(str(exc))}",
                }
            )
        except Exception as exc:
            checks.append(
                {
                    "name": "config",
                    "status": "fail",
                    "detail": f"{cfg_path} invalid: {sanitize_text(str(exc))}",
                }
            )

    # 3. ib_async optional extra installed
    if importlib.util.find_spec("ib_async") is not None:
        checks.append(
            {
                "name": "ibkr_extra",
                "status": "ok",
                "detail": "ib_async installed (clearfills[ibkr])",
            }
        )
    else:
        checks.append(
            {
                "name": "ibkr_extra",
                "status": "warn",
                "detail": "ib_async not installed — run `pip install 'clearfills[ibkr]'` for IBKR",
            }
        )

    # 4. IB Gateway TCP reachability
    reachable, tcp_detail = _check_tcp(ibkr_host, ibkr_port, timeout=1.5)
    checks.append(
        {
            "name": "ib_gateway",
            "status": "ok" if reachable else "warn",
            "detail": tcp_detail,
        }
    )

    # 5. CLEARFILLS_API_KEY & Cloud auth health
    api_key = os.environ.get("CLEARFILLS_API_KEY", "").strip()
    if not api_key:
        checks.append(
            {
                "name": "cloud_auth",
                "status": "warn",
                "detail": "CLEARFILLS_API_KEY not set (optional for local-only mode)",
            }
        )
    else:
        me_url = f"{args.api_url.rstrip('/')}/api/v1/cloud/me"
        req = urllib.request.Request(
            me_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                status_code = getattr(resp, "status", 200)
                body = json.loads(resp.read().decode("utf-8") or "{}")
                plan = body.get("plan") or body.get("tier") or "authenticated"
                checks.append(
                    {
                        "name": "cloud_auth",
                        "status": "ok" if status_code == 200 else "fail",
                        "detail": f"Cloud API authenticated ({plan})",
                    }
                )
        except urllib.error.HTTPError as exc:
            checks.append(
                {
                    "name": "cloud_auth",
                    "status": "fail",
                    "detail": f"Cloud API rejected key (HTTP {exc.code})",
                }
            )
        except Exception as exc:
            checks.append(
                {
                    "name": "cloud_auth",
                    "status": "fail",
                    "detail": f"Cloud API unreachable: {exc}",
                }
            )

    # 6. Local firewall audit chain integrity
    env_data_dir = os.environ.get("CLEARFILLS_DATA_DIR", "").strip()
    candidate_dirs = [
        Path(env_data_dir) if env_data_dir else None,
        Path(".clearfills_data"),
        Path(".clearfills_state") / "firewall",
    ]
    existing_dir = next((p for p in candidate_dirs if p is not None and p.exists()), None)
    try:
        if existing_dir is not None:
            svc = FirewallService.from_data_dir(existing_dir)
            audit = svc.verify_audit()
            if audit.valid:
                checks.append(
                    {
                        "name": "audit_chain",
                        "status": "ok",
                        "detail": f"SHA-256 chain valid ({audit.entry_count} entries in {existing_dir})",
                    }
                )
            else:
                checks.append(
                    {
                        "name": "audit_chain",
                        "status": "fail",
                        "detail": f"Audit chain tampered in {existing_dir}: {audit.error}",
                    }
                )
        else:
            with tempfile.TemporaryDirectory(prefix="clearfills_doctor_") as tmp:
                svc = FirewallService.from_data_dir(tmp, initialize_armed=True)
                audit = svc.verify_audit()
            checks.append(
                {
                    "name": "audit_chain",
                    "status": "ok" if audit.valid else "fail",
                    "detail": f"SHA-256 audit engine healthy ({audit.entry_count} local entries)",
                }
            )
    except Exception as exc:
        checks.append(
            {
                "name": "audit_chain",
                "status": "fail",
                "detail": f"Audit verification error: {exc}",
            }
        )

    has_fail = any(c["status"] == "fail" for c in checks)
    if args.json:
        print(
            json.dumps(
                {
                    "version": __version__,
                    "ok": not has_fail,
                    "checks": checks,
                },
                indent=2,
            )
        )
    else:
        print(f"ClearFills Doctor (v{__version__})")
        print("-" * 64)
        for c in checks:
            print(f"  {_fmt_status(c['status'])} {c['name']:<14s} {c['detail']}")
        print("-" * 64)
        summary = "All checks passed." if not has_fail else "One or more checks failed."
        print(summary)

    return 1 if has_fail else 0


def _cmd_mcp(args: argparse.Namespace, extra_args: list[str]) -> int:
    if args.ibkr:
        if not os.environ.get("CLEARFILLS_DESK_CONFIG", "").strip():
            discovered = _discover_config()
            if discovered is not None and discovered.exists():
                os.environ["CLEARFILLS_DESK_CONFIG"] = str(discovered)
        from clearfills_desk.mcp_server import main as desk_mcp_main

        desk_mcp_main()
        return 0

    from clearfills_firewall.mcp_server import main as firewall_mcp_main

    prev_argv = sys.argv
    try:
        sys.argv = ["clearfills-mcp", *extra_args]
        firewall_mcp_main()
    finally:
        sys.argv = prev_argv
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    cfg_path = _discover_config(args.config)
    if cfg_path is None or not cfg_path.exists():
        print(
            "No config file found. Run `clearfills init` or pass `--config path/to/.clearfills.yaml`.",
            file=sys.stderr,
        )
        return 2

    if importlib.util.find_spec("ib_async") is None:
        print(
            "Missing optional dependency `ib_async` required for IBKR watch mode.\n"
            "Install it with: pip install 'clearfills[ibkr]'",
            file=sys.stderr,
        )
        return 2

    if args.api_url:
        os.environ["CLEARFILLS_API_URL"] = args.api_url
    if args.api_key:
        os.environ["CLEARFILLS_API_KEY"] = args.api_key

    desk_argv = [
        "watch",
        "--config",
        str(cfg_path),
        "--state-dir",
        str(args.state_dir),
        "--interval",
        str(args.interval),
        "--max-slippage-bps",
        str(args.max_slippage_bps),
    ]
    if args.once:
        desk_argv.append("--once")
    if args.dry_run:
        desk_argv.append("--dry-run")

    from clearfills_desk.cli import main as desk_main

    return int(desk_main(desk_argv))


def _cmd_sync(args: argparse.Namespace, extra_args: list[str]) -> int:
    forwarded = list(extra_args)
    if args.source == "ibkr" and "--config" not in forwarded:
        cfg_path = _discover_config()
        if cfg_path is not None and cfg_path.exists():
            forwarded.extend(["--config", str(cfg_path)])

    from clearfills_desk.cli import main as desk_main

    return int(desk_main(["sync", args.source, *forwarded]))


def _cmd_validate(args: argparse.Namespace) -> int:
    cfg_path = _discover_config(args.config)
    if cfg_path is None or not cfg_path.exists():
        print(
            "No config file found. Run `clearfills init` or pass `--config path/to/.clearfills.yaml`.",
            file=sys.stderr,
        )
        return 2

    from clearfills_desk.cli import main as desk_main

    return int(desk_main(["validate", "--config", str(cfg_path)]))


def _redteam_local() -> int:
    print(f"ClearFills Red-Team Verification (local offline firewall, v{__version__})")
    print("-" * 72)

    with tempfile.TemporaryDirectory(prefix="clearfills_redteam_") as tmp:
        svc = FirewallService.from_data_dir(
            data_dir=tmp,
            policy=RiskPolicy(),
            initialize_armed=True,
            ttl_seconds=120,
        )
        portfolio = PortfolioSnapshot(
            account_id="PAPER-SANDBOX",
            nav_usd=1_000_000.0,
            cash_usd=1_000_000.0,
        )

        # 1. Rogue 50,000 NVDA MARKET order -> expects BLOCKED
        p1 = TradeProposal(
            agent_id="redteam-cli",
            venue="ibkr",
            symbol="NVDA",
            side=Side.BUY,
            order_type=OrderType.MARKET,
            quantity=50_000,
            limit_price=135.0,
            stop_price=None,
        )
        d1 = svc.propose(p1, portfolio)
        c1_ok = (not d1.approved) and ("MISSING_STOP_LOSS" in d1.reason_codes or "MAX_ORDER_NOTIONAL_EXCEEDED" in d1.reason_codes)
        print(
            f"  {_fmt_status('PASS' if c1_ok else 'FAIL')} 1. Rogue 50,000 NVDA MARKET   "
            f"-> {d1.status.value} {d1.reason_codes}"
        )

        # 2. Missing stop-loss 100 AAPL LIMIT -> expects BLOCKED (MISSING_STOP_LOSS)
        p2 = TradeProposal(
            agent_id="redteam-cli",
            venue="ibkr",
            symbol="AAPL",
            side=Side.BUY,
            order_type=OrderType.LIMIT,
            quantity=100,
            limit_price=220.0,
            stop_price=None,
        )
        d2 = svc.propose(p2, portfolio)
        c2_ok = (not d2.approved) and ("MISSING_STOP_LOSS" in d2.reason_codes)
        print(
            f"  {_fmt_status('PASS' if c2_ok else 'FAIL')} 2. Missing stop 100 AAPL LIMIT"
            f" -> {d2.status.value} {d2.reason_codes}"
        )

        # 3. Compliant 50 NVDA LIMIT with stop -> APPROVED + single-use replay protection
        p3 = TradeProposal(
            agent_id="redteam-cli",
            venue="ibkr",
            symbol="NVDA",
            side=Side.BUY,
            order_type=OrderType.LIMIT,
            quantity=50,
            limit_price=135.0,
            stop_price=130.0,
        )
        d3 = svc.propose(p3, portfolio)
        first_dispatch = None
        replay_dispatch = None
        if d3.approved and d3.attestation is not None:
            first_dispatch = svc.dispatch_check(d3.attestation, p3)
            replay_dispatch = svc.dispatch_check(d3.attestation, p3)

        c3_ok = (
            d3.approved
            and d3.attestation is not None
            and first_dispatch is not None
            and first_dispatch.allowed
            and replay_dispatch is not None
            and (not replay_dispatch.allowed)
            and replay_dispatch.reason in {"ATTESTATION_REPLAY_DETECTED", "NONCE_ALREADY_SPENT"}
        )
        att_id = d3.attestation.attestation_id if d3.attestation else "none"
        replay_reason = replay_dispatch.reason if replay_dispatch else "n/a"
        print(
            f"  {_fmt_status('PASS' if c3_ok else 'FAIL')} 3. Compliant 50 NVDA + Replay "
            f"-> {d3.status.value} ({att_id[:16]}...) | replay={replay_reason}"
        )

        audit = svc.verify_audit()
        print("-" * 72)
        print(f"  Audit chain: {'VALID' if audit.valid else 'INVALID'} ({audit.entry_count} SHA-256 entries)")

        all_ok = c1_ok and c2_ok and c3_ok and audit.valid
        return 0 if all_ok else 1


def _mcp_http_call(url: str, req_id: int, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"clearfills-cli/{__version__}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15.0) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if "error" in data:
        raise RuntimeError(f"MCP error: {data['error']}")
    result = data.get("result") or {}
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    content = result.get("content") or []
    if content and isinstance(content[0], dict) and isinstance(content[0].get("text"), str):
        return json.loads(content[0]["text"])
    return result


def _redteam_remote(url: str) -> int:
    print(f"ClearFills Red-Team Verification (live MCP: {url})")
    print("-" * 72)

    try:
        # 1. Rogue 50,000 NVDA MARKET order -> expects BLOCKED
        r1 = _mcp_http_call(
            url,
            1,
            "propose_trade",
            {
                "symbol": "NVDA",
                "side": "BUY",
                "quantity": 50_000,
                "order_type": "MARKET",
                "limit_price": 135.0,
                "agent_name": "clearfills-cli",
                "strategy_note": "CLI redteam check 1: rogue market order",
            },
        )
        codes1 = r1.get("reason_codes") or []
        status1 = str(r1.get("verdict") or r1.get("status") or ("APPROVED" if r1.get("approved") else "BLOCKED")).upper()
        c1_ok = (not r1.get("approved", False)) and (
            "LIMIT_ORDERS_ONLY" in codes1 or "MISSING_STOP_LOSS" in codes1 or "MAX_ORDER_NOTIONAL_EXCEEDED" in codes1
        )
        print(f"  {_fmt_status('PASS' if c1_ok else 'FAIL')} 1. Rogue 50,000 NVDA MARKET   -> {status1} {codes1}")

        # 2. Missing stop-loss 100 AAPL LIMIT -> expects BLOCKED (MISSING_STOP_LOSS)
        r2 = _mcp_http_call(
            url,
            2,
            "propose_trade",
            {
                "symbol": "AAPL",
                "side": "BUY",
                "quantity": 100,
                "order_type": "LIMIT",
                "limit_price": 220.0,
                "agent_name": "clearfills-cli",
                "strategy_note": "CLI redteam check 2: missing stop-loss",
            },
        )
        codes2 = r2.get("reason_codes") or []
        status2 = str(r2.get("verdict") or r2.get("status") or ("APPROVED" if r2.get("approved") else "BLOCKED")).upper()
        c2_ok = (not r2.get("approved", False)) and ("MISSING_STOP_LOSS" in codes2)
        print(f"  {_fmt_status('PASS' if c2_ok else 'FAIL')} 2. Missing stop 100 AAPL LIMIT -> {status2} {codes2}")

        # 3. Compliant 50 NVDA LIMIT with stop -> APPROVED + immediate replay -> BLOCKED
        r3 = _mcp_http_call(
            url,
            3,
            "propose_trade",
            {
                "symbol": "NVDA",
                "side": "BUY",
                "quantity": 50,
                "order_type": "LIMIT",
                "limit_price": 135.0,
                "stop_price": 130.0,
                "agent_name": "clearfills-cli",
                "strategy_note": "CLI redteam check 3: compliant limit + stop",
            },
        )
        att_id = r3.get("attestation_id") or (r3.get("attestation") or {}).get("attestation_id")
        replay_res: dict[str, Any] = {}
        if r3.get("approved") and att_id:
            replay_res = _mcp_http_call(
                url,
                4,
                "replay_attestation",
                {
                    "attestation_id": str(att_id),
                    "agent_name": "clearfills-cli",
                },
            )
        replay_codes = replay_res.get("reason_codes") or []
        replay_reason = str(replay_res.get("reason") or (replay_codes[0] if replay_codes else "n/a"))
        replay_blocked = (not replay_res.get("approved", True)) and (
            any(c in {"NONCE_ALREADY_SPENT", "ATTESTATION_REPLAY_DETECTED"} for c in replay_codes)
            or replay_reason in {"NONCE_ALREADY_SPENT", "ATTESTATION_REPLAY_DETECTED"}
        )
        c3_ok = bool(r3.get("approved") and att_id and replay_blocked)
        att_preview = f"{str(att_id)[:16]}..." if att_id else "none"
        print(
            f"  {_fmt_status('PASS' if c3_ok else 'FAIL')} 3. Compliant 50 NVDA + Replay "
            f"-> {'APPROVED' if r3.get('approved') else 'BLOCKED'} ({att_preview}) | replay={replay_reason}"
        )
        print("-" * 72)
        return 0 if (c1_ok and c2_ok and c3_ok) else 1
    except Exception as exc:
        print(f"  {_fmt_status('FAIL')} Remote red-team failed: {exc}", file=sys.stderr)
        print("  Tip: run `clearfills redteam --local` to verify offline.", file=sys.stderr)
        return 1


def _cmd_redteam(args: argparse.Namespace) -> int:
    if args.local:
        return _redteam_local()
    return _redteam_remote(args.url)


def _cmd_serve(args: argparse.Namespace) -> int:
    if importlib.util.find_spec("fastapi") is None or importlib.util.find_spec("uvicorn") is None:
        print(
            "Missing optional dependencies `fastapi` / `uvicorn` required for HTTP server.\n"
            "Install them with: pip install 'clearfills[server]'",
            file=sys.stderr,
        )
        return 2

    os.environ["CLEARFILLS_HOST"] = args.host
    os.environ["CLEARFILLS_PORT"] = str(args.port)
    from clearfills_firewall.server import main as server_main

    server_main()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clearfills",
        description="ClearFills — Deterministic Ed25519 pre-trade risk firewall, MCP server, and IBKR execution guard.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"clearfills {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Generate a safe commented .clearfills.yaml configuration.")
    p_init.add_argument("--mode", choices=["paper", "live"], default="paper", help="Execution mode (default: paper).")
    p_init.add_argument("--host", default="127.0.0.1", help="IB Gateway/TWS host (default: 127.0.0.1).")
    p_init.add_argument("--port", type=int, default=None, help="IB Gateway/TWS port (default: 4002 paper / 4001 live).")
    p_init.add_argument("--output", type=Path, default=Path(DEFAULT_CONFIG_FILENAME), help="Output YAML path (default: .clearfills.yaml).")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing config file.")

    # doctor
    p_doc = sub.add_parser("doctor", help="Run 6 diagnostic checks on local config, IBKR, Cloud auth, and audit chain.")
    p_doc.add_argument("--config", type=Path, default=None, help="Path to .clearfills.yaml.")
    p_doc.add_argument("--json", action="store_true", help="Output diagnostics as JSON.")
    p_doc.add_argument("--api-url", default=DEFAULT_API_URL, help=f"ClearFills Cloud API URL (default: {DEFAULT_API_URL}).")

    # mcp
    p_mcp = sub.add_parser("mcp", help="Run the ClearFills stdio MCP server (firewall by default, or --ibkr).")
    p_mcp.add_argument("--ibkr", action="store_true", help="Run the IBKR broker execution MCP server (clearfills-desk).")

    # watch
    p_watch = sub.add_parser("watch", help="Watch ClearFills Cloud for 1-Tap approved orders and execute via IBKR.")
    p_watch.add_argument("--config", type=Path, default=None, help="Path to .clearfills.yaml (auto-discovered if omitted).")
    p_watch.add_argument("--state-dir", type=Path, default=Path(".clearfills_state"))
    p_watch.add_argument("--dry-run", action="store_true", help="Validate quotes & mint attestations without submitting orders.")
    p_watch.add_argument("--once", action="store_true", help="Run a single poll cycle and exit.")
    p_watch.add_argument("--interval", type=float, default=3.0, help="Poll interval in seconds (default: 3.0).")
    p_watch.add_argument("--max-slippage-bps", type=float, default=50.0, help="Max slippage guard in bps (default: 50.0).")
    p_watch.add_argument("--api-url", default=None, help="Override ClearFills Cloud API URL.")
    p_watch.add_argument("--api-key", default=None, help="Override CLEARFILLS_API_KEY.")

    # sync
    p_sync = sub.add_parser("sync", help="Sync IBKR, EVM wallet, or local snapshot to ClearFills Cloud.")
    p_sync.add_argument("source", choices=["ibkr", "evm", "file"], help="Snapshot source to sync.")

    # validate
    p_val = sub.add_parser("validate", help="Validate .clearfills.yaml and fail-closed IBKR safety guards.")
    p_val.add_argument("--config", type=Path, default=None, help="Path to .clearfills.yaml (auto-discovered if omitted).")

    # redteam
    p_rt = sub.add_parser("redteam", help="Run a 3-step live or offline firewall & replay-protection check.")
    p_rt.add_argument("--local", action="store_true", help="Run 100%% offline against local FirewallService.")
    p_rt.add_argument("--url", default=DEFAULT_CHALLENGE_MCP_URL, help=f"Public MCP challenge URL (default: {DEFAULT_CHALLENGE_MCP_URL}).")

    # serve
    p_srv = sub.add_parser("serve", help="Start the local FastAPI HTTP firewall server (requires clearfills[server]).")
    p_srv.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    p_srv.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080).")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)

    if extra and args.command not in {"mcp", "sync"}:
        parser.error(f"unrecognized arguments: {' '.join(extra)}")

    if args.command == "init":
        return _cmd_init(args)
    if args.command == "doctor":
        return _cmd_doctor(args)
    if args.command == "mcp":
        return _cmd_mcp(args, extra)
    if args.command == "watch":
        return _cmd_watch(args)
    if args.command == "sync":
        return _cmd_sync(args, extra)
    if args.command == "validate":
        return _cmd_validate(args)
    if args.command == "redteam":
        return _cmd_redteam(args)
    if args.command == "serve":
        return _cmd_serve(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
