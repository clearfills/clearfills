"""Tests for attested IBKR Paper & Live execution in ClearFills Desk OS.

All account IDs and hosts in this file are strictly fictitious fixtures.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from clearfills_desk import (
    DeskConfig,
    DeskRuntime,
    IBKRConnectionConfig,
    IBKRExecutionAdapter,
    LiveExecutionSafetyError,
    validate_ibkr_connection,
    verify_connected_accounts,
)
from clearfills_desk.cli import main as cli_main
from clearfills_firewall import PortfolioSnapshot, RiskPolicy, Side, TradeProposal

_ET = ZoneInfo("America/New_York")
_FAKE_LIVE_ACCT = "U0000001"
_FAKE_PAPER_ACCT = "DU0000001"


class _FakeIBClient:
    def __init__(self, accounts: list[str]) -> None:
        self.accounts = accounts
        self.connected = False
        self.placed: list[tuple[object, object]] = []
        self._next_id = 100

    def isConnected(self) -> bool:
        return self.connected

    def connect(self, host: str, port: int, clientId: int = 1, readonly: bool = False) -> None:
        self.connected = True

    def disconnect(self) -> None:
        self.connected = False

    def managedAccounts(self) -> list[str]:
        return list(self.accounts)

    def qualifyContracts(self, *contracts: object) -> list[object]:
        return list(contracts)

    def placeOrder(self, contract: object, order: object) -> object:
        self._next_id += 1
        self.placed.append((contract, order))
        return SimpleNamespace(order=SimpleNamespace(orderId=self._next_id))


def _sample_proposal() -> TradeProposal:
    mon_morning = datetime(2026, 11, 23, 10, 45, tzinfo=_ET).astimezone(timezone.utc)
    return TradeProposal(
        agent_id="strategist",
        venue="ibkr",
        symbol="GOOG",
        side=Side.BUY,
        quantity=50.0,
        limit_price=264.0,
        stop_price=250.0,
        created_at=mon_morning,
    )


def test_live_mode_requires_two_key_opt_in_and_live_port(tmp_path: Path) -> None:
    cfg = DeskConfig(
        desk_id="live-desk",
        desk_name="Live Desk",
        execution_mode="live",
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4001, account_id=_FAKE_LIVE_ACCT, allow_live=True),
    )
    rt = DeskRuntime(config=cfg, state_dir=tmp_path)

    # Missing CLEARFILLS_ALLOW_LIVE=1 env var -> fail closed
    with pytest.raises(LiveExecutionSafetyError, match="CLEARFILLS_ALLOW_LIVE=1"):
        IBKRExecutionAdapter(rt, ib_client=_FakeIBClient([_FAKE_LIVE_ACCT]), env={})

    # Missing allow_live=True in YAML -> fail closed
    no_flag_cfg = cfg.model_copy(
        update={"ibkr": IBKRConnectionConfig(host="127.0.0.1", port=4001, account_id=_FAKE_LIVE_ACCT, allow_live=False)}
    )
    with pytest.raises(LiveExecutionSafetyError, match="allow_live: true"):
        IBKRExecutionAdapter(DeskRuntime(no_flag_cfg, tmp_path / "nf"), env={"CLEARFILLS_ALLOW_LIVE": "1"})

    # Paper port in live mode -> fail closed
    bad_port_cfg = cfg.model_copy(
        update={"ibkr": IBKRConnectionConfig(host="127.0.0.1", port=4002, account_id=_FAKE_LIVE_ACCT, allow_live=True)}
    )
    with pytest.raises(LiveExecutionSafetyError, match="refuses port 4002"):
        IBKRExecutionAdapter(DeskRuntime(bad_port_cfg, tmp_path / "p"), env={"CLEARFILLS_ALLOW_LIVE": "1"})

    # Paper DU account in live mode -> fail closed
    bad_acct_cfg = cfg.model_copy(
        update={"ibkr": IBKRConnectionConfig(host="127.0.0.1", port=4001, account_id=_FAKE_PAPER_ACCT, allow_live=True)}
    )
    with pytest.raises(LiveExecutionSafetyError, match="refuses paper account"):
        IBKRExecutionAdapter(DeskRuntime(bad_acct_cfg, tmp_path / "a"), env={"CLEARFILLS_ALLOW_LIVE": "1"})


def test_host_guard_loopback_and_optional_tailnet_relay() -> None:
    # Public IP always rejected
    with pytest.raises(LiveExecutionSafetyError, match="non-loopback"):
        validate_ibkr_connection(IBKRConnectionConfig(host="8.8.8.8", port=4002), "paper")

    # Tailscale CGNAT rejected unless allow_tailnet_relay=True
    with pytest.raises(LiveExecutionSafetyError, match="non-loopback"):
        validate_ibkr_connection(IBKRConnectionConfig(host="100.64.0.10", port=4002), "paper")

    validate_ibkr_connection(
        IBKRConnectionConfig(host="100.64.0.10", port=4002, allow_tailnet_relay=True),
        "paper",
    )
    validate_ibkr_connection(
        IBKRConnectionConfig(host="relay.example.ts.net", port=4002, allow_tailnet_relay=True),
        "paper",
    )


def test_paper_mode_and_shadow_mode_fail_closed(tmp_path: Path) -> None:
    cfg = DeskConfig(
        desk_id="paper-desk",
        desk_name="Paper Desk",
        execution_mode="paper",
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4001),
    )
    with pytest.raises(LiveExecutionSafetyError, match="Paper mode refuses port 4001"):
        IBKRExecutionAdapter(DeskRuntime(cfg, tmp_path), env={})

    # Shadow mode must never instantiate broker execution adapter
    shadow_cfg = DeskConfig(
        desk_id="shadow-desk",
        desk_name="Shadow Desk",
        execution_mode="shadow",
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4002),
    )
    with pytest.raises(LiveExecutionSafetyError, match="refuses execution_mode='shadow'"):
        IBKRExecutionAdapter(DeskRuntime(shadow_cfg, tmp_path / "s"), env={})

    # Paper session connected to live account must fail closed
    with pytest.raises(LiveExecutionSafetyError, match="non-paper account"):
        verify_connected_accounts([_FAKE_LIVE_ACCT], _FAKE_PAPER_ACCT, "paper")


def test_live_attested_order_executes_once_and_blocks_replay(tmp_path: Path) -> None:
    cfg = DeskConfig(
        desk_id="live-desk",
        desk_name="Live Desk",
        execution_mode="live",
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4001, account_id=_FAKE_LIVE_ACCT, allow_live=True),
        risk=RiskPolicy(max_order_notional_usd=25_000.0, max_risk_per_trade_pct=2.0),
    )
    rt = DeskRuntime(config=cfg, state_dir=tmp_path)
    fake_ib = _FakeIBClient([_FAKE_LIVE_ACCT])
    adapter = IBKRExecutionAdapter(rt, ib_client=fake_ib, env={"CLEARFILLS_ALLOW_LIVE": "1"})

    proposal = _sample_proposal()
    pf = PortfolioSnapshot(nav_usd=100_000.0, cash_usd=100_000.0, session_entries=0)
    decision = rt.evaluate_proposal(proposal, pf)
    assert decision.approved is True
    assert decision.attestation is not None

    receipt = adapter.submit_attested_order(proposal, decision.attestation)
    assert receipt.execution_mode == "live"
    assert receipt.symbol == "GOOG"
    assert receipt.quantity == 50.0
    assert len(receipt.order_ids) == 2  # Parent LMT + protective STP child
    assert len(fake_ib.placed) == 2
    assert _FAKE_LIVE_ACCT not in receipt.model_dump_json()  # Sanitized receipt

    # Replay of same single-use attestation must fail closed
    with pytest.raises(LiveExecutionSafetyError, match="Dispatch rejected"):
        adapter.submit_attested_order(proposal, decision.attestation)


def test_cli_validate_live_config_sanitized(capsys, monkeypatch) -> None:
    live_yaml = Path(__file__).resolve().parents[1] / "config" / "desk_rules.live.example.yaml"
    monkeypatch.delenv("CLEARFILLS_ALLOW_LIVE", raising=False)
    assert cli_main(["validate", "--config", str(live_yaml)]) == 2

    monkeypatch.setenv("CLEARFILLS_ALLOW_LIVE", "1")
    assert cli_main(["validate", "--config", str(live_yaml)]) == 0
    out = capsys.readouterr().out
    assert "U0000000" not in out
    assert '"valid": true' in out
