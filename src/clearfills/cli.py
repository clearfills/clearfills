"""Unified CLI for ClearFills (`clearfills init|doctor|mcp|watch|sync|validate|redteam|benchmark|compile-policy|serve|prove|verify-proof`)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
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
        c1_ok = (
            (not d1.approved)
            and ("MARKET_ORDER_FORBIDDEN" in d1.reason_codes)
            and ("MISSING_STOP_LOSS" in d1.reason_codes or "MAX_ORDER_NOTIONAL_EXCEEDED" in d1.reason_codes)
        )
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


_TLSN_INSTALL_HINT = (
    "Install the real TLSNotary CLI (Rust toolchain required):\n"
    "  cargo install --git https://github.com/tlsnotary/tlsn tlsn-cli\n"
    "Or place prebuilt `tlsn` / `tlsn-prover` / `tlsn-verifier` binaries in:\n"
    "  ~/.clearfills/bin/\n"
    "Or deploy your own TLSNotary notary server on Fly.io:\n"
    "  cd src/deploy/tlsn-notary && fly deploy"
)

_FALLBACK_BROKER_DEFAULTS: dict[str, tuple[str, str]] = {
    "alpaca": ("api.alpaca.markets", "/v2/orders/{order_id}"),
    "alpaca_paper": ("paper-api.alpaca.markets", "/v2/orders/{order_id}"),
    "kalshi": ("api.elections.kalshi.com", "/trade-api/v2/portfolio/orders/{order_id}"),
    "ibkr_flex": ("gdcdyn.interactivebrokers.com", "/Universal/servlet/FlexStatementService.GetStatement"),
}


def _collect_broker_auth_from_env(broker: str) -> tuple[dict[str, str], dict[str, str]]:
    """Read broker credentials from standard environment variables without logging them."""
    headers: dict[str, str] = {"Accept": "application/json"}
    query_params: dict[str, str] = {}
    if broker in ("alpaca", "alpaca_paper"):
        key_id = os.environ.get("APCA_API_KEY_ID", "").strip()
        secret = os.environ.get("APCA_API_SECRET_KEY", "").strip()
        if key_id:
            headers["APCA-API-KEY-ID"] = key_id
        if secret:
            headers["APCA-API-SECRET-KEY"] = secret
    elif broker == "kalshi":
        access_key = os.environ.get("KALSHI_ACCESS_KEY", os.environ.get("KALSHI_API_KEY", "")).strip()
        signature = os.environ.get("KALSHI_ACCESS_SIGNATURE", "").strip()
        if access_key:
            headers["KALSHI-ACCESS-KEY"] = access_key
        if signature:
            headers["KALSHI-ACCESS-SIGNATURE"] = signature
    elif broker in ("ibkr_flex", "ibkr"):
        headers["Accept"] = "application/xml"
        token = os.environ.get("IBKR_FLEX_TOKEN", "").strip()
        if token:
            query_params["t"] = token
        query_params["v"] = "3"
    return headers, query_params


def _detect_tlsn_bin_fallback(role: str, explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        exp = explicit.expanduser()
        if exp.is_file() and os.access(exp, os.X_OK):
            return exp
    names = ("tlsn-prover", "tlsn") if role == "prover" else ("tlsn-verifier", "tlsn")
    local_dir = Path.home() / ".clearfills" / "bin"
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found)
        cand = local_dir / name
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def _cmd_prove(args: argparse.Namespace) -> int:
    if args.install_hint:
        print(_TLSN_INSTALL_HINT)
        return 0

    headers, query_params = _collect_broker_auth_from_env(args.broker)
    if args.broker in ("ibkr_flex", "ibkr") and args.order_id:
        query_params["q"] = args.order_id

    output_path = args.output or Path(f"{args.order_id or args.broker}.presentation.tlsn")

    try:
        from clearfills_arena.tlsn_prover import (
            BROKER_REDACTION_PROFILES,
            TLSNotaryBinaryNotFoundError,
            TLSNotaryConfig,
            TLSNotaryRunner,
            build_http_request_bytes,
            build_redaction_plan,
        )
    except ImportError:
        # Standalone open-core fallback (zero extra dependencies)
        default_server, path_tpl = _FALLBACK_BROKER_DEFAULTS[args.broker]
        server_name = (args.server_name or default_server).strip().lower()
        path = args.request_path or path_tpl.format(order_id=args.order_id or "")
        if args.plan_only:
            payload = {
                "broker": args.broker,
                "server_name": server_name,
                "path": path,
                "notary_host": args.notary_host,
                "notary_port": args.notary_port,
                "notary_tls": not args.no_notary_tls,
            }
            print(json.dumps(payload, indent=2))
            return 0
        binary = _detect_tlsn_bin_fallback("prover", args.tlsn_bin)
        if binary is None:
            print(
                "Error: TLSNotary prover binary (`tlsn-prover` / `tlsn`) not found on PATH "
                "or in ~/.clearfills/bin/. ClearFills never fakes MPC-TLS proofs.\n"
                f"{_TLSN_INSTALL_HINT}",
                file=sys.stderr,
            )
            return 1
        cmd = [str(binary)]
        if binary.name == "tlsn":
            cmd.append("prove")
        cmd.extend(
            [
                "--notary-host",
                args.notary_host,
                "--notary-port",
                str(args.notary_port),
                "--server-name",
                server_name,
                "--output",
                str(output_path),
            ]
        )
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            print(f"TLSNotary prover failed: {(proc.stderr or proc.stdout).strip()}", file=sys.stderr)
            return 1
        print(f"Wrote MPC-TLS presentation: {output_path}")
        return 0

    cfg = TLSNotaryConfig(
        notary_host=args.notary_host,
        notary_port=args.notary_port,
        notary_tls=not args.no_notary_tls,
        tlsn_bin=str(args.tlsn_bin) if args.tlsn_bin else None,
        max_sent_data=args.max_sent_data,
        max_recv_data=args.max_recv_data,
    )
    runner = TLSNotaryRunner(config=cfg)

    if args.plan_only:
        profile = BROKER_REDACTION_PROFILES[args.broker]
        resolved_server = (args.server_name or profile.default_server_name).strip().lower()
        path = args.request_path or profile.default_path_template.format(order_id=args.order_id or "")
        req_bytes = build_http_request_bytes(
            method="GET",
            path=path,
            host=resolved_server,
            headers=headers,
            query_params=query_params,
        )
        plan = build_redaction_plan(
            broker=args.broker,
            server_name=resolved_server,
            request_bytes=req_bytes,
        )
        if args.json:
            print(json.dumps(plan.to_tlsn_commit_spec(), indent=2))
        else:
            print(f"ClearFills TLSNotary Redaction Plan ({plan.broker} @ {plan.server_name})")
            print(f"  Request bytes:   {plan.request_bytes_len}")
            print(f"  Redacted ranges: {[(r.start, r.end, r.label) for r in plan.sent_redacted_ranges]}")
            print(f"  Revealed ranges: {[(r.start, r.end) for r in plan.sent_revealed_ranges]}")
        return 0

    try:
        result = runner.prove_broker_fill(
            broker=args.broker,
            order_id=args.order_id or "",
            output_path=output_path,
            headers=headers,
            query_params=query_params,
            server_name=args.server_name,
            request_path=args.request_path,
        )
    except TLSNotaryBinaryNotFoundError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "TLSN_BINARY_NOT_FOUND",
                        "detail": str(exc),
                        "install_hint": exc.install_hint,
                    },
                    indent=2,
                )
            )
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        print(f"Wrote MPC-TLS presentation: {result.presentation_path}")
        print(f"  SHA-256: {result.presentation_sha256}")
        print(f"  Server:  {result.server_name}")
        print(f"  Notary:  {result.notary_host}:{result.notary_port}")
    return 0


def _verify_ed25519_envelope_standalone(
    bundle_path: Path,
    expected_server_name: str | None,
    trusted_pubkeys_pem: list[str] | None,
) -> dict[str, Any]:
    """Zero-extra-dep stdlib + cryptography verifier for Ed25519 notary envelope JSON bundles."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        raw = json.loads(bundle_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {
            "valid": False,
            "proof_type": "broker_reconciled_notary_envelope",
            "trust_level": "ed25519_notary_envelope",
            "path": str(bundle_path),
            "errors": [f"INVALID_JSON_BUNDLE: {exc}"],
        }

    proof = raw.get("proof", raw) if isinstance(raw, dict) else {}
    att = proof.get("notary_attestation") or {}
    errors: list[str] = []

    domain = str(att.get("server_domain") or "").strip().lower()
    if expected_server_name and domain != expected_server_name.strip().lower():
        errors.append(
            f"SERVER_NAME_MISMATCH: expected={expected_server_name.strip().lower()!r} got={domain!r}"
        )

    commitment_payload = {
        "venue": str(proof.get("venue") or "").strip().lower(),
        "symbol": str(proof.get("symbol") or "").strip().upper(),
        "side": str(proof.get("side") or "").strip().upper(),
        "filled_qty": float(proof.get("filled_qty") or 0.0),
        "avg_fill_price": float(proof.get("avg_fill_price") or 0.0),
        "broker_order_id": str(proof.get("broker_order_id") or "").strip(),
        "filled_at": str(proof.get("filled_at") or "").strip(),
    }
    expected_commit = hashlib.sha256(
        json.dumps(commitment_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    got_commit = str(proof.get("transcript_commitment_sha256") or "").strip().lower()
    if not hmac.compare_digest(got_commit, expected_commit):
        errors.append("TRANSCRIPT_COMMITMENT_MISMATCH: revealed fill fields do not match commitment")

    signing_payload = {
        "protocol_version": att.get("protocol_version", "tlsnotary-v0.1-alpha"),
        "server_domain": domain,
        "cert_chain_sha256": str(att.get("cert_chain_sha256") or "").strip().lower(),
        "notary_id": att.get("notary_id", ""),
        "session_timestamp_utc": att.get("session_timestamp_utc", ""),
        "account_id_redacted": bool(att.get("account_id_redacted", False)),
        "transcript_commitment_sha256": proof.get("transcript_commitment_sha256", ""),
    }
    signing_bytes = json.dumps(
        signing_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")

    sig_verified: bool | None = None
    sig_b64 = att.get("notary_signature_b64")
    pems_to_try = list(trusted_pubkeys_pem) if trusted_pubkeys_pem is not None else (
        [att["notary_pubkey_pem"]] if att.get("notary_pubkey_pem") else []
    )
    if trusted_pubkeys_pem is not None and not sig_b64:
        sig_verified = False
        errors.append("MISSING_NOTARY_SIGNATURE")
    elif sig_b64 and pems_to_try:
        try:
            sig_bytes = base64.b64decode(sig_b64, validate=True)
        except Exception:  # noqa: BLE001
            sig_bytes = b""
        verified_any = False
        for pem in pems_to_try:
            try:
                key = serialization.load_pem_public_key(pem.encode("utf-8"))
                if isinstance(key, Ed25519PublicKey):
                    key.verify(sig_bytes, signing_bytes)
                    verified_any = True
                    break
            except (InvalidSignature, ValueError):
                continue
        sig_verified = verified_any
        if not verified_any:
            errors.append("INVALID_NOTARY_SIGNATURE")

    return {
        "valid": len(errors) == 0 and sig_verified is not False,
        "proof_type": "broker_reconciled_notary_envelope",
        "trust_level": "ed25519_notary_envelope",
        "path": str(bundle_path),
        "server_name": domain,
        "session_timestamp_utc": att.get("session_timestamp_utc", ""),
        "signature_verified": sig_verified,
        "fill": {
            "venue": proof.get("venue"),
            "symbol": proof.get("symbol"),
            "side": proof.get("side"),
            "filled_qty": proof.get("filled_qty"),
            "avg_fill_price": proof.get("avg_fill_price"),
            "broker_order_id": proof.get("broker_order_id"),
            "filled_at": proof.get("filled_at"),
        },
        "errors": errors,
    }


def _cmd_verify_proof(args: argparse.Namespace) -> int:
    trusted_pems: list[str] | None = None
    if args.notary_pubkey is not None:
        if not args.notary_pubkey.is_file():
            print(f"Notary public key file not found: {args.notary_pubkey}", file=sys.stderr)
            return 1
        trusted_pems = [args.notary_pubkey.read_text(encoding="utf-8")]

    try:
        from clearfills_arena.tlsn_prover import TLSNotaryConfig, verify_clearfills_proof_bundle

        cfg = TLSNotaryConfig(tlsn_bin=str(args.tlsn_bin) if args.tlsn_bin else None)
        report = verify_clearfills_proof_bundle(
            args.proof_path,
            expected_server_name=args.server_name,
            trusted_notary_pubkeys_pem=trusted_pems,
            config=cfg,
        )
    except ImportError:
        # Standalone open-core fallback
        bundle = args.proof_path.expanduser().resolve()
        if not bundle.is_file():
            report = {
                "valid": False,
                "proof_type": "unknown",
                "trust_level": "unknown",
                "path": str(bundle),
                "errors": [f"PROOF_FILE_NOT_FOUND: {bundle}"],
            }
        elif bundle.name.endswith(".presentation.tlsn") or bundle.suffix == ".tlsn":
            binary = _detect_tlsn_bin_fallback("verifier", args.tlsn_bin)
            if binary is None:
                report = {
                    "valid": False,
                    "proof_type": "tlsnotary_mpc_tls",
                    "trust_level": "mpc_tls_cryptographic",
                    "path": str(bundle),
                    "errors": [
                        "TLSN_BINARY_NOT_FOUND: tlsn-verifier / tlsn not installed. ClearFills never fakes verification."
                    ],
                    "install_hint": _TLSN_INSTALL_HINT,
                }
            else:
                cmd = [str(binary)]
                if binary.name == "tlsn":
                    cmd.append("verify")
                cmd.extend(["--presentation", str(bundle), "--format", "json"])
                if args.notary_pubkey:
                    cmd.extend(["--notary-pubkey", str(args.notary_pubkey)])
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if proc.returncode != 0:
                    report = {
                        "valid": False,
                        "proof_type": "tlsnotary_mpc_tls",
                        "trust_level": "mpc_tls_cryptographic",
                        "path": str(bundle),
                        "errors": [f"TLSN_VERIFICATION_FAILED: {(proc.stderr or proc.stdout).strip()}"],
                    }
                else:
                    parsed = json.loads(proc.stdout)
                    got_server = str(parsed.get("server_name") or "").strip().lower()
                    errs: list[str] = []
                    if args.server_name and got_server != args.server_name.strip().lower():
                        errs.append(
                            f"SERVER_NAME_MISMATCH: expected={args.server_name.strip().lower()!r} got={got_server!r}"
                        )
                    report = {
                        "valid": len(errs) == 0,
                        "proof_type": "tlsnotary_mpc_tls",
                        "trust_level": "mpc_tls_cryptographic",
                        "path": str(bundle),
                        "server_name": got_server,
                        "session_timestamp_utc": str(parsed.get("session_timestamp_utc") or parsed.get("time") or ""),
                        "errors": errs,
                    }
        else:
            report = _verify_ed25519_envelope_standalone(bundle, args.server_name, trusted_pems)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        status = "PASS" if report.get("valid") else "FAIL"
        print(f"ClearFills Proof Verification ({report.get('proof_type', 'unknown')})")
        print("-" * 64)
        print(f"  {_fmt_status(status)} valid={report.get('valid')} trust_level={report.get('trust_level')}")
        if report.get("server_name"):
            print(f"  Server:    {report['server_name']}")
        if report.get("session_timestamp_utc"):
            print(f"  Timestamp: {report['session_timestamp_utc']}")
        if report.get("errors"):
            for err in report["errors"]:
                print(f"  Error:     {err}")
        print("-" * 64)

    return 0 if report.get("valid") else 1


def _cmd_benchmark(args: argparse.Namespace) -> int:
    from clearfills_firewall import run_safety_benchmark

    report = run_safety_benchmark()
    all_ok = (
        report.attacks_blocked == report.attacks_total
        and report.legit_approved == report.legit_total
        and report.audit_chain_valid
    )

    if args.json:
        print(json.dumps(report.model_dump(mode="json"), indent=2))
        return 0 if all_ok else 1

    print(f"ClearFills 25-Scenario Adversarial Safety Benchmark (v{__version__})")
    print("-" * 108)
    print(f"  {'ID':<6s} {'STATUS':<6s} {'OUTCOME':<9s} {'LAT(ms)':>8s}  {'SCENARIO':<42s} {'REASON CODES'}")
    print("-" * 108)
    for r in report.results:
        tag = _fmt_status("PASS" if r.passed else "FAIL")
        codes = ", ".join(r.reason_codes) if r.reason_codes else "APPROVED"
        print(
            f"  {r.scenario_id:<6s} {tag} {r.actual_outcome:<9s} {r.latency_ms:>8.3f}  {r.name:<42s} {codes}"
        )
    print("-" * 108)
    print(
        f"  Attacks blocked: {report.attacks_blocked}/{report.attacks_total} ({report.block_rate_pct:.1f}%)"
        f" | Legit approved: {report.legit_approved}/{report.legit_total} ({report.false_positive_rate_pct:.1f}% false positives)"
    )
    print(
        f"  Latency:         avg {report.avg_latency_ms:.3f} ms | p99 {report.p99_latency_ms:.3f} ms"
        f" | Audit chain: {'VALID' if report.audit_chain_valid else 'INVALID'} ({report.audit_entry_count} SHA-256 entries)"
    )
    return 0 if all_ok else 1


def _cmd_compile_policy(args: argparse.Namespace) -> int:
    from clearfills_firewall import compile_natural_language_policy

    result = compile_natural_language_policy(args.rules)

    if args.output is not None:
        out_path: Path = args.output
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(result.yaml_text, encoding="utf-8")

    if args.json:
        payload = result.model_dump(mode="json")
        if args.output is not None:
            payload["output_path"] = str(args.output)
        print(json.dumps(payload, indent=2))
        return 0 if result.self_test_passed else 1

    print(f"ClearFills Deterministic Policy Compiler (v{__version__})")
    print("-" * 76)
    print(f"  Extracted rules ({len(result.extracted_rules)}):")
    for rule in result.extracted_rules:
        print(f"    - {rule.field}: {rule.value!r} ({rule.description})")
    if result.warnings:
        print("  Warnings:")
        for w in result.warnings:
            print(f"    ! {w}")
    status_tag = _fmt_status("PASS" if result.self_test_passed else "FAIL")
    print(f"  Self-test: {status_tag} {result.self_test_summary}")
    for chk in result.self_test_checks:
        chk_tag = _fmt_status("PASS" if chk.passed else "FAIL")
        print(f"    {chk_tag} {chk.rule:<26s} expected={chk.expected} actual={chk.actual}")
    if args.output is not None:
        print(f"  Saved YAML: {args.output}")
    print("-" * 76)
    print(result.yaml_text.rstrip())
    return 0 if result.self_test_passed else 1


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

    # benchmark
    p_bench = sub.add_parser(
        "benchmark",
        help="Run the 25-scenario adversarial safety benchmark against the local FirewallService.",
    )
    p_bench.add_argument("--json", action="store_true", help="Output structured JSON report.")

    # compile-policy
    p_cp = sub.add_parser(
        "compile-policy",
        help="Deterministically compile plain-English risk rules into a verified RiskPolicy YAML.",
    )
    p_cp.add_argument("rules", help="Plain-English trading and risk constraints to compile.")
    p_cp.add_argument("--json", action="store_true", help="Output structured JSON result.")
    p_cp.add_argument("--output", type=Path, default=None, help="Optional path to write compiled policy YAML.")

    # serve
    p_srv = sub.add_parser("serve", help="Start the local FastAPI HTTP firewall server (requires clearfills[server]).")
    p_srv.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    p_srv.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080).")

    # prove
    p_prove = sub.add_parser(
        "prove",
        help="Generate a cryptographic TLSNotary MPC-TLS proof (.presentation.tlsn) for a broker fill.",
    )
    p_prove.add_argument(
        "--broker",
        choices=["alpaca", "alpaca_paper", "kalshi", "ibkr_flex"],
        default="alpaca",
        help="Broker redaction profile (default: alpaca).",
    )
    p_prove.add_argument("--order-id", default="", help="Broker order ID (or IBKR Flex query ID).")
    p_prove.add_argument("--output", type=Path, default=None, help="Output .presentation.tlsn file path.")
    p_prove.add_argument("--notary-host", default="notary.clearfills.com", help="TLSNotary notary server host.")
    p_prove.add_argument("--notary-port", type=int, default=7047, help="TLSNotary notary server port (default: 7047).")
    p_prove.add_argument("--no-notary-tls", action="store_true", help="Disable TLS when connecting to local dev notary.")
    p_prove.add_argument("--server-name", default=None, help="Override broker TLS server hostname.")
    p_prove.add_argument("--request-path", default=None, help="Override broker HTTP request path.")
    p_prove.add_argument("--tlsn-bin", type=Path, default=None, help="Explicit path to tlsn / tlsn-prover binary.")
    p_prove.add_argument("--max-sent-data", type=int, default=4096, help="Max MPC-TLS sent bytes (default: 4096).")
    p_prove.add_argument("--max-recv-data", type=int, default=16384, help="Max MPC-TLS recv bytes (default: 16384).")
    p_prove.add_argument("--plan-only", action="store_true", help="Output byte-range RedactionPlan without running MPC-TLS.")
    p_prove.add_argument("--install-hint", action="store_true", help="Print TLSNotary CLI installation instructions and exit.")
    p_prove.add_argument("--json", action="store_true", help="Output structured JSON.")

    # verify-proof
    p_vproof = sub.add_parser(
        "verify-proof",
        help="Verify a TLSNotary (.presentation.tlsn) or Ed25519 notary envelope (.json) fill proof.",
    )
    p_vproof.add_argument("proof_path", type=Path, help="Path to .presentation.tlsn or Ed25519 notary JSON bundle.")
    p_vproof.add_argument("--server-name", default=None, help="Expected broker TLS server name (required for .presentation.tlsn).")
    p_vproof.add_argument("--notary-pubkey", type=Path, default=None, help="Path to trusted notary public key PEM file.")
    p_vproof.add_argument("--tlsn-bin", type=Path, default=None, help="Explicit path to tlsn / tlsn-verifier binary.")
    p_vproof.add_argument("--json", action="store_true", help="Output structured JSON with explicit trust_level.")

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
    if args.command == "benchmark":
        return _cmd_benchmark(args)
    if args.command == "compile-policy":
        return _cmd_compile_policy(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "prove":
        return _cmd_prove(args)
    if args.command == "verify-proof":
        return _cmd_verify_proof(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
