"""Security Hardening Track 2 tests for clearfills-desk.

Covers:
- Gap 3: Single canonical WebAuthn verifier (pinned keys only, rpIdHash, origin,
  webauthn.get, UP+UV required, mandatory nonce-bound challenge, credential_id pinning).
- Gap 4: Fail-closed live mode passkey default (`LIVE_PASSKEY_PIN_REQUIRED`) vs paper mode.
- Gap 2: Mark-to-market RealizedPnL + UnrealizedPnL in `ibkr.py` + automatic per-poll
  latching kill-switch (`DAILY_DRAWDOWN_BREACHED`) in `worker.py`.
- Gap 5: Split-key verify-only Ed25519 policy ticket verification (`authority_public_key_pem`).
- Gap 8: Honest fill receipts (`quoted_reference_price` vs `fill_price` / `actual_fill_price`).
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clearfills_desk import (
    ApprovalWorker,
    DeskConfig,
    DeskRuntime,
    IBKRConnectionConfig,
    IBKRExecutionAdapter,
    SplitKeyTicketVerifier,
    canonical_order_digest,
    verify_webauthn_assertion,
)
from clearfills_firewall import (
    AttestationAuthority,
    KillSwitch,
    OrderType,
    RiskPolicy,
    Side,
    TradeProposal,
    default_allocation_sleeves,
)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _gen_p256() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, _b64u(der)


def _build_assertion(
    record: dict[str, Any],
    priv: ec.EllipticCurvePrivateKey,
    *,
    nonce: str | None = "nonce_track2_0001",
    rp_id: str = "clearfills.com",
    origin: str = "https://clearfills.com",
    flags: int = 0x05,
    ceremony_type: str = "webauthn.get",
    credential_id: str = "cred_yubikey_01",
    embed_pubkey_b64: str | None = None,
    sign_count: int = 1,
) -> dict[str, Any]:
    order_hash = record.get("approval_hash") or canonical_order_digest(record)
    if nonce is not None:
        challenge = _b64u(hashlib.sha256(f"{nonce}:{order_hash}".encode("utf-8")).digest())
    else:
        # Nonce-less challenge (must be rejected)
        challenge = _b64u(bytes.fromhex(order_hash))

    auth_data = (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + bytes([flags])
        + int(sign_count).to_bytes(4, "big")
    )
    client_data = json.dumps(
        {"type": ceremony_type, "challenge": challenge, "origin": origin},
        separators=(",", ":"),
    ).encode("utf-8")
    sig = priv.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))

    out: dict[str, Any] = {
        "credential_id": credential_id,
        "challenge": challenge,
        "authenticator_data": _b64u(auth_data),
        "client_data_json": _b64u(client_data),
        "signature": _b64u(sig),
    }
    if nonce is not None:
        out["challenge_nonce"] = nonce
    if embed_pubkey_b64 is not None:
        out["public_key_spki_b64"] = embed_pubkey_b64
    return out


class _ConfigurableIB:
    def __init__(
        self,
        *,
        accounts: list[str] | None = None,
        summary_rows: list[Any] | None = None,
        positions: list[Any] | None = None,
        bid: float = 100.20,
        ask: float = 100.25,
        last: float = 100.22,
        fill_on_place: tuple[str, float, float] | None = None,
    ) -> None:
        self._accounts = accounts or ["DU0000001"]
        self._connected = False
        self.summary_rows = summary_rows if summary_rows is not None else [
            SimpleNamespace(tag="NetLiquidation", currency="USD", value="500000.00"),
            SimpleNamespace(tag="BuyingPower", currency="USD", value="1000000.00"),
            SimpleNamespace(tag="SettledCash", currency="USD", value="250000.00"),
            SimpleNamespace(tag="RealizedPnL", currency="USD", value="0.00"),
            SimpleNamespace(tag="UnrealizedPnL", currency="USD", value="0.00"),
        ]
        self._positions = positions or []
        self.bid = bid
        self.ask = ask
        self.last = last
        self.fill_on_place = fill_on_place
        self.placed: list[tuple[Any, Any]] = []
        self._next_oid = 5001

    def isConnected(self) -> bool:
        return self._connected

    def connect(self, host: str, port: int, clientId: int = 1, readonly: bool = False) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def managedAccounts(self) -> list[str]:
        return list(self._accounts)

    def accountSummary(self, account: str = "") -> list[Any]:
        return list(self.summary_rows)

    def portfolio(self, account: str = "") -> list[Any]:
        return list(self._positions)

    def openTrades(self) -> list[Any]:
        return []

    def qualifyContracts(self, *contracts: Any) -> list[Any]:
        return list(contracts)

    def reqTickers(self, *contracts: Any) -> list[Any]:
        return [
            SimpleNamespace(
                bid=self.bid,
                ask=self.ask,
                last=self.last,
                close=self.last,
                vwap=self.last,
                marketDataType=1,
            )
        ]

    def placeOrder(self, contract: Any, order: Any) -> Any:
        oid = self._next_oid
        self._next_oid += 1
        self.placed.append((contract, order))
        if self.fill_on_place is not None:
            st, qty, avg_px = self.fill_on_place
            return SimpleNamespace(
                order=SimpleNamespace(orderId=oid),
                orderStatus=SimpleNamespace(status=st, filled=qty, avgFillPrice=avg_px),
            )
        return SimpleNamespace(
            order=SimpleNamespace(orderId=oid),
            orderStatus=SimpleNamespace(status="Submitted", filled=0.0, avgFillPrice=0.0),
        )


def _sample_record(approval_id: str = "apr_sec_001") -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "status": "approved",
        "venue": "ibkr",
        "symbol": "SGOV",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 100.0,
        "limit_price": 100.25,
        "agent_id": "allocator",
    }


def _make_transport(records: list[dict[str, Any]], reported: list[dict[str, Any]]):
    queue = list(records)

    def transport(method: str, path: str, body: Any) -> Any:
        if path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path.startswith("/api/v1/cloud/approvals"):
            batch = list(queue)
            queue.clear()
            return batch
        if path.endswith("/claim"):
            return {"claimed": True}
        if path.endswith("/executed"):
            reported.append(body or {})
            return {"ok": True}
        raise AssertionError(f"Unexpected request: {method} {path}")

    return transport


# ---------------------------------------------------------------------------
# Gap 3: Single Canonical WebAuthn Verifier
# ---------------------------------------------------------------------------


def test_canonical_webauthn_verifier_strict_checks() -> None:
    priv, spki_b64 = _gen_p256()
    attacker_priv, attacker_spki_b64 = _gen_p256()
    base = _sample_record()

    # 1. Valid assertion passes
    rec_ok = dict(base)
    rec_ok["webauthn_proof"] = _build_assertion(rec_ok, priv)
    ok, _ = verify_webauthn_assertion(rec_ok, [spki_b64], trusted_credential_ids=["cred_yubikey_01"])
    assert ok is True

    # 2. NEVER trusts public key carried inside assertion when no pinned key is configured
    rec_unpinned = dict(base)
    rec_unpinned["webauthn_proof"] = _build_assertion(
        rec_unpinned, attacker_priv, embed_pubkey_b64=attacker_spki_b64
    )
    ok, msg = verify_webauthn_assertion(rec_unpinned, [])
    assert ok is False
    assert "pinned" in msg.lower()

    # 3. Wrong rpIdHash rejected
    rec_bad_rp = dict(base)
    rec_bad_rp["webauthn_proof"] = _build_assertion(rec_bad_rp, priv, rp_id="evil.example.com")
    ok, msg = verify_webauthn_assertion(rec_bad_rp, [spki_b64])
    assert ok is False
    assert "rpidhash" in msg.lower()

    # 4. Wrong origin rejected
    rec_bad_origin = dict(base)
    rec_bad_origin["webauthn_proof"] = _build_assertion(
        rec_bad_origin, priv, origin="https://phishing.example.com"
    )
    ok, msg = verify_webauthn_assertion(rec_bad_origin, [spki_b64])
    assert ok is False
    assert "origin" in msg.lower()

    # 5. Missing UV bit (UP=1, UV=0 -> 0x01) rejected unconditionally
    rec_no_uv = dict(base)
    rec_no_uv["webauthn_proof"] = _build_assertion(rec_no_uv, priv, flags=0x01)
    ok, msg = verify_webauthn_assertion(rec_no_uv, [spki_b64])
    assert ok is False
    assert "uv" in msg.lower()

    # 6. Nonce-less challenge rejected
    rec_no_nonce = dict(base)
    rec_no_nonce["webauthn_proof"] = _build_assertion(rec_no_nonce, priv, nonce=None)
    ok, msg = verify_webauthn_assertion(rec_no_nonce, [spki_b64])
    assert ok is False
    assert "nonce" in msg.lower()

    # 7. Credential ID mismatch rejected when trusted_credential_ids is pinned
    ok, msg = verify_webauthn_assertion(
        rec_ok, [spki_b64], trusted_credential_ids=["cred_other_key"]
    )
    assert ok is False
    assert "credential_id" in msg.lower()


# ---------------------------------------------------------------------------
# Gap 4: Fail-Closed Live Cosign Default
# ---------------------------------------------------------------------------


def test_live_mode_fails_closed_without_pinned_passkey_and_paper_allows_default(tmp_path: Path) -> None:
    live_cfg = DeskConfig(
        desk_id="live-fail-closed",
        desk_name="Live Fail Closed",
        execution_mode="live",
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4001, account_id="U9999999", allow_live=True),
        risk=RiskPolicy(sleeves=default_allocation_sleeves()),
    )
    live_ib = _ConfigurableIB(accounts=["U9999999"])
    live_adapter = IBKRExecutionAdapter(
        DeskRuntime(live_cfg, state_dir=tmp_path / "live"),
        ib_client=live_ib,
        env={"CLEARFILLS_ALLOW_LIVE": "1"},
    )
    reported: list[dict[str, Any]] = []
    live_worker = ApprovalWorker(
        adapter=live_adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([_sample_record("apr_live_nopin")], reported),
    )
    assert live_worker.require_webauthn_cosign is True
    assert live_worker.require_passkey_cosign is True

    outcomes = live_worker.poll_once()
    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "cosign_rejected"
    assert "LIVE_PASSKEY_PIN_REQUIRED" in outcomes[0]["detail"]
    assert len(live_ib.placed) == 0
    assert reported[0]["status"] == "cosign_rejected"

    # Paper (DU*) account defaults to require_webauthn_cosign=False
    paper_cfg = DeskConfig(
        desk_id="paper-default",
        desk_name="Paper Default",
        execution_mode="paper",
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4002, account_id="DU1234567", allow_live=False),
        risk=RiskPolicy(sleeves=default_allocation_sleeves()),
    )
    paper_ib = _ConfigurableIB(accounts=["DU1234567"])
    paper_adapter = IBKRExecutionAdapter(
        DeskRuntime(paper_cfg, state_dir=tmp_path / "paper"),
        ib_client=paper_ib,
        env={},
    )
    paper_worker = ApprovalWorker(
        adapter=paper_adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([_sample_record("apr_paper_ok")], []),
    )
    assert paper_worker.require_webauthn_cosign is False
    assert paper_worker.require_passkey_cosign is False
    paper_out = paper_worker.poll_once()
    assert len(paper_out) == 1
    assert paper_out[0]["status"] == "submitted"
    assert len(paper_ib.placed) == 1


# ---------------------------------------------------------------------------
# Gap 2: Mark-to-Market Drawdown Monitor + Automatic Latching Kill-Switch
# ---------------------------------------------------------------------------


def test_mtm_unrealized_loss_latches_killswitch_on_empty_poll_and_blocks_future_orders(
    tmp_path: Path,
) -> None:
    # RealizedPnL = +$500, UnrealizedPnL = -$12,500 on $500,000 NAV => -2.4% drawdown >= 2.0% limit!
    ib = _ConfigurableIB(
        accounts=["DU1234567"],
        summary_rows=[
            SimpleNamespace(tag="NetLiquidation", currency="USD", value="500000.00"),
            SimpleNamespace(tag="SettledCash", currency="USD", value="250000.00"),
            SimpleNamespace(tag="RealizedPnL", currency="USD", value="500.00"),
            SimpleNamespace(tag="UnrealizedPnL", currency="USD", value="-12500.00"),
            SimpleNamespace(tag="DailyPnL", currency="USD", value="500.00"),
        ],
    )
    cfg = DeskConfig(
        desk_id="mtm-desk",
        desk_name="MTM Desk",
        execution_mode="paper",
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4002, account_id="DU1234567", allow_live=False),
        risk=RiskPolicy(max_daily_loss_pct=2.0, sleeves=default_allocation_sleeves()),
    )
    state_dir = tmp_path / "mtm_state"
    rt = DeskRuntime(cfg, state_dir=state_dir)
    adapter = IBKRExecutionAdapter(rt, ib_client=ib, env={})

    pf = adapter.get_portfolio()
    assert pf["realized_pnl_usd"] == pytest.approx(500.0)
    assert pf["unrealized_pnl_usd"] == pytest.approx(-12500.0)
    assert pf["daily_pnl_usd"] == pytest.approx(-12000.0)

    # Poll cycle with ZERO pending orders must still latch killswitch.json!
    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([], []),
    )
    assert worker.poll_once() == []

    ks_path = state_dir / "firewall" / "killswitch.json"
    assert ks_path.exists()
    ks_state = KillSwitch(ks_path).status()
    assert ks_state.tripped is True
    assert ks_state.reason == "DAILY_DRAWDOWN_BREACHED"

    # Even if the market recovers next poll, kill-switch remains latched and hard-blocks orders!
    ib.summary_rows = [
        SimpleNamespace(tag="NetLiquidation", currency="USD", value="500000.00"),
        SimpleNamespace(tag="SettledCash", currency="USD", value="250000.00"),
        SimpleNamespace(tag="RealizedPnL", currency="USD", value="0.00"),
        SimpleNamespace(tag="UnrealizedPnL", currency="USD", value="0.00"),
    ]
    reported: list[dict[str, Any]] = []
    worker2 = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([_sample_record("apr_after_latch")], reported),
    )
    outcomes = worker2.poll_once()
    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "firewall_denied"
    assert "KILL_SWITCH_TRIPPED" in outcomes[0]["reason_codes"]
    assert len(ib.placed) == 0


# ---------------------------------------------------------------------------
# Gap 5: Split-Key Verify-Only Ed25519 Ticket Verification
# ---------------------------------------------------------------------------


def test_split_key_verify_only_ticket_verification_and_replay_protection(tmp_path: Path) -> None:
    # Cloud authority holds the Ed25519 private key; Desk worker ONLY gets the public PEM.
    cloud_authority = AttestationAuthority(ttl_seconds=120)
    cloud_pub_pem = cloud_authority.public_key_pem()

    # Verify-only loader must reject private keys
    priv_pem = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    with pytest.raises(ValueError, match="verify-only"):
        SplitKeyTicketVerifier(priv_pem)

    ib = _ConfigurableIB(accounts=["DU1234567"])
    cfg = DeskConfig(
        desk_id="split-key-desk",
        desk_name="Split Key Desk",
        execution_mode="paper",
        authority_public_key_pem=cloud_pub_pem,
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4002, account_id="DU1234567", allow_live=False),
        risk=RiskPolicy(sleeves=default_allocation_sleeves()),
    )
    rt = DeskRuntime(cfg, state_dir=tmp_path / "split_state")
    adapter = IBKRExecutionAdapter(rt, ib_client=ib, env={})

    # 1. Missing policy ticket -> fails closed
    reported: list[dict[str, Any]] = []
    worker_missing = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([_sample_record("apr_no_ticket")], reported),
    )
    res_missing = worker_missing.poll_once()
    assert res_missing[0]["status"] == "firewall_denied"
    assert "SPLIT_KEY_TICKET_REQUIRED" in res_missing[0]["reason_codes"]
    assert len(ib.placed) == 0

    # 2. Valid Cloud-issued ticket -> verified with public key ONLY and submitted
    proposal = TradeProposal(
        proposal_id="prop_cloud_001",
        agent_id="allocator",
        venue="ibkr",
        symbol="SGOV",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=100.0,
        limit_price=100.25,
    )
    ticket = cloud_authority.issue(proposal)
    valid_rec = _sample_record("apr_valid_ticket")
    valid_rec["proposal_id"] = "prop_cloud_001"
    valid_rec["policy_ticket"] = ticket.model_dump(mode="json")

    worker_ok = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([valid_rec], reported),
    )
    res_ok = worker_ok.poll_once()
    assert len(res_ok) == 1
    assert res_ok[0]["status"] == "submitted"
    assert res_ok[0]["attestation_id"] == ticket.attestation_id
    assert len(ib.placed) == 1

    # 3. Replay of exact same ticket -> rejected
    worker_replay = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([valid_rec], reported),
    )
    res_replay = worker_replay.poll_once()
    assert res_replay[0]["status"] == "firewall_denied"
    assert "ATTESTATION_REPLAY_DETECTED" in res_replay[0]["reason_codes"]
    assert len(ib.placed) == 1

    # 4. Tampered quantity against valid Cloud ticket -> rejected
    ticket2 = cloud_authority.issue(proposal)
    tampered_rec = _sample_record("apr_tampered_ticket")
    tampered_rec["proposal_id"] = "prop_cloud_001"
    tampered_rec["quantity"] = 500.0  # Tampered!
    tampered_rec["policy_ticket"] = ticket2.model_dump(mode="json")
    worker_tampered = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([tampered_rec], reported),
    )
    res_tampered = worker_tampered.poll_once()
    assert res_tampered[0]["status"] == "firewall_denied"
    assert "ORDER_HASH_MISMATCH" in res_tampered[0]["reason_codes"]
    assert len(ib.placed) == 1

    # 5. Ticket signed by rogue key -> rejected
    rogue_authority = AttestationAuthority(ttl_seconds=120)
    rogue_ticket = rogue_authority.issue(proposal)
    rogue_rec = _sample_record("apr_rogue_ticket")
    rogue_rec["proposal_id"] = "prop_cloud_001"
    rogue_rec["policy_ticket"] = rogue_ticket.model_dump(mode="json")
    worker_rogue = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([rogue_rec], reported),
    )
    res_rogue = worker_rogue.poll_once()
    assert res_rogue[0]["status"] == "firewall_denied"
    assert "UNKNOWN_KEY_ID" in res_rogue[0]["reason_codes"]
    assert len(ib.placed) == 1

    # 6. Expired ticket -> rejected
    expired_ticket = cloud_authority.issue(
        proposal,
        now=datetime.now(timezone.utc) - timedelta(seconds=300),
        ttl_seconds=60,
    )
    expired_rec = _sample_record("apr_expired_ticket")
    expired_rec["proposal_id"] = "prop_cloud_001"
    expired_rec["policy_ticket"] = expired_ticket.model_dump(mode="json")
    worker_exp = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([expired_rec], reported),
    )
    res_exp = worker_exp.poll_once()
    assert res_exp[0]["status"] == "firewall_denied"
    assert "ATTESTATION_EXPIRED" in res_exp[0]["reason_codes"]
    assert len(ib.placed) == 1


# ---------------------------------------------------------------------------
# Gap 8: Honest Fill Receipts
# ---------------------------------------------------------------------------


def test_honest_fill_receipts_submitted_vs_actual_broker_fill(tmp_path: Path) -> None:
    cfg = DeskConfig(
        desk_id="fill-receipt-desk",
        desk_name="Fill Receipt Desk",
        execution_mode="paper",
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4002, account_id="DU1234567", allow_live=False),
        risk=RiskPolicy(sleeves=default_allocation_sleeves()),
    )

    # Case 1: Submitted (not yet filled) -> fill_price MUST be None, quoted_reference_price == ask
    ib_sub = _ConfigurableIB(accounts=["DU1234567"], ask=100.28, fill_on_place=None)
    adapter_sub = IBKRExecutionAdapter(DeskRuntime(cfg, tmp_path / "sub"), ib_client=ib_sub, env={})
    reported_sub: list[dict[str, Any]] = []
    worker_sub = ApprovalWorker(
        adapter=adapter_sub,
        api_key="cf_test",
        cloud_transport=_make_transport([_sample_record("apr_sub_01")], reported_sub),
    )
    out_sub = worker_sub.poll_once()
    assert out_sub[0]["status"] == "submitted"
    assert out_sub[0]["quoted_reference_price"] == pytest.approx(100.28)
    assert out_sub[0]["fill_price"] is None
    assert out_sub[0]["actual_fill_price"] is None
    assert out_sub[0]["filled_qty"] == 0.0
    assert reported_sub[0]["status"] == "submitted"
    assert reported_sub[0]["fill_price"] is None
    assert reported_sub[0]["quoted_reference_price"] == pytest.approx(100.28)

    # Case 2: Actual broker fill reported -> status == "filled", fill_price == actual_fill_price == avgFillPrice
    ib_fill = _ConfigurableIB(
        accounts=["DU1234567"],
        ask=100.28,
        fill_on_place=("Filled", 100.0, 100.24),
    )
    adapter_fill = IBKRExecutionAdapter(DeskRuntime(cfg, tmp_path / "fill"), ib_client=ib_fill, env={})
    reported_fill: list[dict[str, Any]] = []
    worker_fill = ApprovalWorker(
        adapter=adapter_fill,
        api_key="cf_test",
        cloud_transport=_make_transport([_sample_record("apr_fill_01")], reported_fill),
    )
    out_fill = worker_fill.poll_once()
    assert out_fill[0]["status"] == "filled"
    assert out_fill[0]["quoted_reference_price"] == pytest.approx(100.28)
    assert out_fill[0]["fill_price"] == pytest.approx(100.24)
    assert out_fill[0]["actual_fill_price"] == pytest.approx(100.24)
    assert out_fill[0]["filled_qty"] == pytest.approx(100.0)
    assert reported_fill[0]["status"] == "filled"
    assert reported_fill[0]["fill_price"] == pytest.approx(100.24)
    assert reported_fill[0]["actual_fill_price"] == pytest.approx(100.24)


# ---------------------------------------------------------------------------
# Final Hardening Track 2: py_webauthn Delegation + signCount Rollback Protection
# ---------------------------------------------------------------------------


def test_py_webauthn_verifies_pinned_p256_and_rejects_sign_count_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import webauthn

    priv, spki_b64 = _gen_p256()
    base = _sample_record("apr_pywebauthn_001")

    # Spy on webauthn.verify_authentication_response to prove delegation
    calls: list[dict[str, Any]] = []
    real_verify = webauthn.verify_authentication_response

    def _spy_verify(**kwargs: Any) -> Any:
        calls.append(kwargs)
        return real_verify(**kwargs)

    monkeypatch.setattr(webauthn, "verify_authentication_response", _spy_verify)

    # 1. Valid pinned P-256 assertion with sign_count=10 > current_sign_count=9 succeeds
    rec_10 = dict(base)
    rec_10["webauthn_proof"] = _build_assertion(
        rec_10,
        priv,
        nonce="nonce_sc_10",
        rp_id="clearfills.com",
        origin="https://clearfills.com",
        flags=0x05,
        credential_id="cred_yubikey_01",
        sign_count=10,
    )
    res = verify_webauthn_assertion(
        rec_10,
        [spki_b64],
        expected_rp_id="clearfills.com",
        expected_origin="https://clearfills.com",
        trusted_credential_ids=["cred_yubikey_01"],
        current_sign_count=9,
    )
    ok, detail = res
    assert ok is True
    assert res.verified is True
    assert res.new_sign_count == 10
    assert res.credential_id == "cred_yubikey_01"
    assert res.user_verified is True
    assert "py_webauthn" in detail.lower()
    assert len(calls) == 1
    assert calls[0]["require_user_verification"] is True
    assert calls[0]["credential_current_sign_count"] == 9
    assert calls[0]["expected_rp_id"] == "clearfills.com"
    assert calls[0]["expected_origin"] == "https://clearfills.com"

    # 2. Equal sign_count (10 <= 10) rejected as cloned authenticator / rollback
    res_eq = verify_webauthn_assertion(
        rec_10,
        [spki_b64],
        expected_rp_id="clearfills.com",
        expected_origin="https://clearfills.com",
        current_sign_count=10,
    )
    assert res_eq.verified is False
    assert "sign_count" in res_eq.detail.lower() or "cloned" in res_eq.detail.lower()

    # 3. Lower sign_count (7 <= 10) rejected as cloned authenticator / rollback
    rec_7 = dict(base)
    rec_7["webauthn_proof"] = _build_assertion(
        rec_7,
        priv,
        nonce="nonce_sc_7",
        credential_id="cred_yubikey_01",
        sign_count=7,
    )
    res_low = verify_webauthn_assertion(
        rec_7,
        [spki_b64],
        current_sign_count=10,
    )
    assert res_low.verified is False
    assert "sign_count" in res_low.detail.lower() or "cloned" in res_low.detail.lower()


def test_worker_persists_passkey_sign_counts_atomically_0600_and_blocks_rollback(
    tmp_path: Path,
) -> None:
    priv, spki_b64 = _gen_p256()
    state_dir = tmp_path / "sign_count_state"
    cfg = DeskConfig(
        desk_id="sign-count-desk",
        desk_name="Sign Count Desk",
        execution_mode="paper",
        ibkr=IBKRConnectionConfig(host="127.0.0.1", port=4002, account_id="DU1234567", allow_live=False),
        risk=RiskPolicy(sleeves=default_allocation_sleeves()),
    )
    ib = _ConfigurableIB(accounts=["DU1234567"])
    adapter = IBKRExecutionAdapter(DeskRuntime(cfg, state_dir=state_dir), ib_client=ib, env={})

    # Order 1: sign_count = 5 -> accepted, persisted to passkey_sign_counts.json (0600)
    rec1 = _sample_record("apr_sc_01")
    rec1["webauthn_proof"] = _build_assertion(
        rec1, priv, nonce="nonce_w_01", credential_id="cred_yk_prod", sign_count=5
    )
    reported1: list[dict[str, Any]] = []
    worker1 = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([rec1], reported1),
        trusted_passkey_spki_b64=[spki_b64],
        trusted_credential_ids=["cred_yk_prod"],
    )
    out1 = worker1.poll_once()
    assert len(out1) == 1
    assert out1[0]["status"] == "submitted"
    assert len(ib.placed) == 1

    sc_path = state_dir / "passkey_sign_counts.json"
    assert sc_path.exists()
    assert (sc_path.stat().st_mode & 0o777) == 0o600
    assert json.loads(sc_path.read_text(encoding="utf-8")) == {"cred_yk_prod": 5}

    # Order 2 (fresh worker instance simulating restart): sign_count = 5 (cloned/rollback) -> REJECTED
    rec2_rollback = _sample_record("apr_sc_02_rollback")
    rec2_rollback["webauthn_proof"] = _build_assertion(
        rec2_rollback, priv, nonce="nonce_w_02", credential_id="cred_yk_prod", sign_count=5
    )
    reported2: list[dict[str, Any]] = []
    worker2 = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([rec2_rollback], reported2),
        trusted_passkey_spki_b64=[spki_b64],
        trusted_credential_ids=["cred_yk_prod"],
    )
    out2 = worker2.poll_once()
    assert len(out2) == 1
    assert out2[0]["status"] == "cosign_rejected"
    assert "sign_count" in out2[0]["detail"].lower() or "cloned" in out2[0]["detail"].lower()
    assert len(ib.placed) == 1
    assert json.loads(sc_path.read_text(encoding="utf-8")) == {"cred_yk_prod": 5}

    # Order 3: sign_count = 3 (strictly lower rollback) -> REJECTED
    rec3_lower = _sample_record("apr_sc_03_lower")
    rec3_lower["webauthn_proof"] = _build_assertion(
        rec3_lower, priv, nonce="nonce_w_03", credential_id="cred_yk_prod", sign_count=3
    )
    worker3 = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([rec3_lower], []),
        trusted_passkey_spki_b64=[spki_b64],
        trusted_credential_ids=["cred_yk_prod"],
    )
    out3 = worker3.poll_once()
    assert len(out3) == 1
    assert out3[0]["status"] == "cosign_rejected"
    assert len(ib.placed) == 1

    # Order 4: sign_count = 6 (monotonic increment) -> ACCEPTED and persisted as 6
    rec4_inc = _sample_record("apr_sc_04_inc")
    rec4_inc["webauthn_proof"] = _build_assertion(
        rec4_inc, priv, nonce="nonce_w_04", credential_id="cred_yk_prod", sign_count=6
    )
    worker4 = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test",
        cloud_transport=_make_transport([rec4_inc], []),
        trusted_passkey_spki_b64=[spki_b64],
        trusted_credential_ids=["cred_yk_prod"],
    )
    out4 = worker4.poll_once()
    assert len(out4) == 1
    assert out4[0]["status"] == "submitted"
    assert len(ib.placed) == 2
    assert json.loads(sc_path.read_text(encoding="utf-8")) == {"cred_yk_prod": 6}
    assert (sc_path.stat().st_mode & 0o777) == 0o600
