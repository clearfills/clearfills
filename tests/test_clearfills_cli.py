"""Tests for the unified `clearfills` package API and CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import clearfills
from clearfills import FirewallService, PortfolioSnapshot, RiskPolicy, TradeProposal
from clearfills.cli import main as cli_main


def test_top_level_exports_and_version() -> None:
    assert clearfills.__version__ == "0.5.1"
    assert FirewallService is not None
    assert TradeProposal is not None
    assert PortfolioSnapshot is not None
    assert RiskPolicy is not None


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "clearfills 0.5.1" in captured.out


def test_cli_init_paper_and_live_and_force(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    paper_cfg = tmp_path / ".clearfills.yaml"
    rc = cli_main(["init", "--output", str(paper_cfg)])
    assert rc == 0
    assert paper_cfg.exists()
    text = paper_cfg.read_text(encoding="utf-8")
    assert "execution_mode: paper" in text
    assert "port: 4002" in text
    assert "allow_live: false" in text
    assert "cash_equivalent:" in text
    assert "SGOV" in text
    assert "core_index:" in text
    assert "VT" in text

    out = capsys.readouterr().out
    assert "clearfills doctor" in out
    assert "clearfills watch" in out
    assert "clearfills mcp" in out

    # Refuses overwrite without --force
    rc_dup = cli_main(["init", "--output", str(paper_cfg)])
    assert rc_dup == 1

    # Overwrites cleanly with --force and --mode live
    rc_live = cli_main(["init", "--mode", "live", "--output", str(paper_cfg), "--force"])
    assert rc_live == 0
    live_text = paper_cfg.read_text(encoding="utf-8")
    assert "execution_mode: live" in live_text
    assert "port: 4001" in live_text
    assert "allow_live: true" in live_text


def test_cli_validate_generated_paper_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / ".clearfills.yaml"
    assert cli_main(["init", "--output", str(cfg)]) == 0
    capsys.readouterr()

    rc = cli_main(["validate", "--config", str(cfg)])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["valid"] is True
    assert data["execution_mode"] == "paper"
    assert data["ibkr_port"] == 4002
    assert data["allow_live"] is False


def test_cli_doctor_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / ".clearfills.yaml"
    assert cli_main(["init", "--output", str(cfg)]) == 0
    capsys.readouterr()

    monkeypatch.delenv("CLEARFILLS_API_KEY", raising=False)
    monkeypatch.delenv("CLEARFILLS_DATA_DIR", raising=False)

    rc = cli_main(["doctor", "--config", str(cfg), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "0.5.1"
    assert payload["ok"] is True
    names = [c["name"] for c in payload["checks"]]
    assert names == [
        "runtime",
        "config",
        "ibkr_extra",
        "ib_gateway",
        "cloud_auth",
        "audit_chain",
    ]
    by_name = {c["name"]: c for c in payload["checks"]}
    assert by_name["runtime"]["status"] == "ok"
    assert by_name["config"]["status"] == "ok"
    assert by_name["audit_chain"]["status"] == "ok"


def test_cli_redteam_local(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli_main(["redteam", "--local"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "NVDA MARKET" in out
    assert "AAPL LIMIT" in out
    assert "ATTESTATION_REPLAY_DETECTED" in out
    assert "Audit chain: VALID" in out
