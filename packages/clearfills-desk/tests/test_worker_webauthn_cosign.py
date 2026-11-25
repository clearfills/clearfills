"""Offline unit tests for local hardware-bound WebAuthn co-signature verification in ApprovalWorker."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from clearfills_desk import (
    ApprovalWorker,
    DeskConfig,
    DeskRuntime,
    IBKRConnectionConfig,
    IBKRExecutionAdapter,
)
from clearfills_desk.worker import verify_local_webauthn_cosign
from clearfills_firewall import RiskPolicy, default_allocation_sleeves


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _derive_order_bound_challenge(nonce_b64: str, approval_hash: str) -> str:
    return _b64u(hashlib.sha256(f"{nonce_b64}:{approval_hash}".encode("utf-8")).digest())


def _generate_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, _b64u(pub_der)


def _sign_order_bound_p256(
    priv: ec.EllipticCurvePrivateKey,
    *,
    nonce_b64: str,
    approval_hash: str,
    up_flag: bool = True,
    ceremony_type: str = "webauthn.get",
    rp_id: str = "clearfills.com",
) -> dict[str, Any]:
    challenge = _derive_order_bound_challenge(nonce_b64, approval_hash)
    flags = 0x05 if up_flag else 0x00
    auth_data = hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([flags]) + (1).to_bytes(4, "big")
    client_data = json.dumps(
        {
            "type": ceremony_type,
            "challenge": challenge,
            "origin": f"https://{rp_id}",
        }
    ).encode("utf-8")
    signed_payload = auth_data + hashlib.sha256(client_data).digest()
    signature = priv.sign(signed_payload, ec.ECDSA(hashes.SHA256()))
    return {
        "credential_id": "cred_touchid_local_001",
        "challenge": challenge,
        "challenge_nonce": nonce_b64,
        "challenge_binding": "sha256(nonce:approval_hash)",
        "approval_hash": approval_hash,
        "authenticator_data": _b64u(auth_data),
        "client_data_json": _b64u(client_data),
        "signature": _b64u(signature),
    }


class _FakeIB:
    """In-memory mock of ib_async.IB for deterministic offline ApprovalWorker tests."""

    def __init__(self, *, bid: float = 100.20, ask: float = 100.25, last: float = 100.22) -> None:
        self._connected = False
        self.bid = bid
        self.ask = ask
        self.last = last
        self.placed: list[tuple[Any, Any]] = []
        self.quote_calls: list[Any] = []
        self._next_oid = 9001

    def isConnected(self) -> bool:
        return self._connected

    def connect(self, host: str, port: int, clientId: int = 1, readonly: bool = False) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def managedAccounts(self) -> list[str]:
        return ["U0000001"]

    def accountSummary(self, account: str = "") -> list[Any]:
        return [
            SimpleNamespace(tag="NetLiquidation", currency="USD", value="500000.00"),
            SimpleNamespace(tag="BuyingPower", currency="USD", value="1000000.00"),
            SimpleNamespace(tag="SettledCash", currency="USD", value="250000.00"),
            SimpleNamespace(tag="DailyPnL", currency="USD", value="0.00"),
        ]

    def portfolio(self, account: str = "") -> list[Any]:
        return []

    def openTrades(self) -> list[Any]:
        return []

    def qualifyContracts(self, *contracts: Any) -> list[Any]:
        return list(contracts)

    def reqTickers(self, *contracts: Any) -> list[Any]:
        self.quote_calls.extend(contracts)
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
        return SimpleNamespace(order=SimpleNamespace(orderId=oid))


def _make_adapter(tmp_path: Path) -> tuple[IBKRExecutionAdapter, _FakeIB]:
    cfg = DeskConfig(
        desk_id="cosign-worker-desk",
        desk_name="ClearFills Co-Sign Desk",
        execution_mode="live",
        human_confirm_above_usd=25_000.0,
        ibkr=IBKRConnectionConfig(
            host="127.0.0.1",
            port=4001,
            account_id="U0000001",
            allow_live=True,
        ),
        risk=RiskPolicy(
            max_risk_per_trade_pct=1.0,
            max_total_heat_pct=12.0,
            max_daily_loss_pct=2.0,
            max_order_notional_usd=50_000.0,
            require_stop_loss=True,
            max_entries_per_session=4,
            block_last_session_of_week=False,
            sleeves=default_allocation_sleeves(),
        ),
    )
    runtime = DeskRuntime(cfg, state_dir=tmp_path / "desk_state")
    fake_ib = _FakeIB()
    adapter = IBKRExecutionAdapter(runtime, ib_client=fake_ib, env={"CLEARFILLS_ALLOW_LIVE": "1"})
    return adapter, fake_ib


def _make_transport(record: dict[str, Any], reported: list[dict[str, Any]]):
    approval_id = record["approval_id"]

    def transport(method: str, path: str, body: Any) -> Any:
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            return [record]
        if method == "POST" and path == f"/api/v1/cloud/approvals/{approval_id}/claim":
            return {"approval_id": approval_id, "claimed": True}
        if method == "POST" and path == f"/api/v1/cloud/approvals/{approval_id}/executed":
            reported.append(body)
            return {"approval_id": approval_id, "status": body.get("status")}
        raise AssertionError(f"Unexpected cloud request: {method} {path}")

    return transport


def test_valid_local_p256_cosign_passes_and_submits_to_ibkr(tmp_path: Path) -> None:
    adapter, fake_ib = _make_adapter(tmp_path)
    priv, spki_b64 = _generate_p256_keypair()
    nonce_b64 = _b64u(b"deterministic_test_nonce_24b")
    approval_hash = hashlib.sha256(b"SGOV:BUY:200:100.25:ibkr").hexdigest()
    proof = _sign_order_bound_p256(priv, nonce_b64=nonce_b64, approval_hash=approval_hash)

    record = {
        "approval_id": "apr_cosign_ok_001",
        "status": "approved",
        "venue": "ibkr",
        "symbol": "SGOV",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 200,
        "limit_price": 100.25,
        "approval_hash": approval_hash,
        "webauthn_proof": proof,
    }
    reported: list[dict[str, Any]] = []
    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_sk_test",
        cloud_transport=_make_transport(record, reported),
        trusted_passkey_spki_b64=[spki_b64],
        require_webauthn_cosign=True,
    )

    outcomes = worker.poll_once()
    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "submitted"
    assert outcomes[0]["broker_order_id"] == "9001"
    assert len(fake_ib.placed) == 1
    assert len(reported) == 1
    assert reported[0]["status"] == "submitted"


def test_missing_webauthn_proof_fails_closed_cosign_rejected(tmp_path: Path) -> None:
    adapter, fake_ib = _make_adapter(tmp_path)
    _, spki_b64 = _generate_p256_keypair()

    record = {
        "approval_id": "apr_cosign_missing_001",
        "status": "approved",
        "venue": "ibkr",
        "symbol": "SGOV",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 200,
        "limit_price": 100.25,
        "approval_hash": hashlib.sha256(b"SGOV:BUY:200:100.25:ibkr").hexdigest(),
    }
    reported: list[dict[str, Any]] = []
    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_sk_test",
        cloud_transport=_make_transport(record, reported),
        trusted_passkey_spki_b64=[spki_b64],
        require_webauthn_cosign=True,
    )

    outcomes = worker.poll_once()
    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "cosign_rejected"
    assert "missing webauthn_proof" in outcomes[0]["detail"].lower()
    assert len(fake_ib.placed) == 0
    assert len(fake_ib.quote_calls) == 0
    assert len(reported) == 1
    assert reported[0]["status"] == "cosign_rejected"


def test_tampered_approval_hash_fails_closed_cosign_rejected(tmp_path: Path) -> None:
    adapter, fake_ib = _make_adapter(tmp_path)
    priv, spki_b64 = _generate_p256_keypair()
    nonce_b64 = _b64u(b"nonce_for_tamper_test_0001")
    original_hash = hashlib.sha256(b"SGOV:BUY:200:100.25:ibkr").hexdigest()
    tampered_hash = hashlib.sha256(b"GME:BUY:5000:100.25:ibkr").hexdigest()
    proof = _sign_order_bound_p256(priv, nonce_b64=nonce_b64, approval_hash=original_hash)
    # Remove proof-side approval_hash so verification binds strictly against record["approval_hash"]
    proof.pop("approval_hash")

    record = {
        "approval_id": "apr_cosign_tampered_001",
        "status": "approved",
        "venue": "ibkr",
        "symbol": "SGOV",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 200,
        "limit_price": 100.25,
        "approval_hash": tampered_hash,
        "webauthn_proof": proof,
    }
    reported: list[dict[str, Any]] = []
    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_sk_test",
        cloud_transport=_make_transport(record, reported),
        trusted_passkey_spki_b64=[spki_b64],
        require_webauthn_cosign=True,
    )

    outcomes = worker.poll_once()
    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "cosign_rejected"
    assert "sha256(nonce:approval_hash)" in outcomes[0]["detail"]
    assert len(fake_ib.placed) == 0
    assert len(fake_ib.quote_calls) == 0
    assert reported[0]["status"] == "cosign_rejected"


def test_wrong_signing_key_fails_closed_cosign_rejected(tmp_path: Path) -> None:
    adapter, fake_ib = _make_adapter(tmp_path)
    _, trusted_spki_b64 = _generate_p256_keypair()
    attacker_priv, _ = _generate_p256_keypair()

    nonce_b64 = _b64u(b"nonce_for_wrong_key_test_1")
    approval_hash = hashlib.sha256(b"SGOV:BUY:200:100.25:ibkr").hexdigest()
    proof = _sign_order_bound_p256(attacker_priv, nonce_b64=nonce_b64, approval_hash=approval_hash)

    record = {
        "approval_id": "apr_cosign_wrong_key_001",
        "status": "approved",
        "venue": "ibkr",
        "symbol": "SGOV",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 200,
        "limit_price": 100.25,
        "approval_hash": approval_hash,
        "webauthn_proof": proof,
    }
    reported: list[dict[str, Any]] = []
    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_sk_test",
        cloud_transport=_make_transport(record, reported),
        trusted_passkey_spki_b64=[trusted_spki_b64],
    )

    outcomes = worker.poll_once()
    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "cosign_rejected"
    assert "signature failed" in outcomes[0]["detail"].lower()
    assert len(fake_ib.placed) == 0
    assert len(fake_ib.quote_calls) == 0
    assert reported[0]["status"] == "cosign_rejected"


def test_verify_local_webauthn_cosign_checks_up_flag_ceremony_and_rsa() -> None:
    priv, spki_b64 = _generate_p256_keypair()
    nonce_b64 = _b64u(b"nonce_flag_and_rsa_checks")
    approval_hash = hashlib.sha256(b"VT:BUY:10:120.0:ibkr").hexdigest()

    # Missing UP flag rejected
    no_up_proof = _sign_order_bound_p256(priv, nonce_b64=nonce_b64, approval_hash=approval_hash, up_flag=False)
    ok, msg = verify_local_webauthn_cosign({"approval_hash": approval_hash, "webauthn_proof": no_up_proof}, [spki_b64])
    assert ok is False
    assert "up" in msg.lower()

    # Wrong ceremony type rejected
    bad_type_proof = _sign_order_bound_p256(
        priv, nonce_b64=nonce_b64, approval_hash=approval_hash, ceremony_type="webauthn.create"
    )
    ok, msg = verify_local_webauthn_cosign(
        {"approval_hash": approval_hash, "webauthn_proof": bad_type_proof}, [spki_b64]
    )
    assert ok is False
    assert "webauthn.get" in msg

    # RSA SPKI key verification succeeds
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_spki = _b64u(
        rsa_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    challenge = _derive_order_bound_challenge(nonce_b64, approval_hash)
    auth_data = hashlib.sha256(b"clearfills.com").digest() + bytes([0x05]) + (1).to_bytes(4, "big")
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": challenge, "origin": "https://clearfills.com"}
    ).encode("utf-8")
    sig = rsa_priv.sign(auth_data + hashlib.sha256(client_data).digest(), padding.PKCS1v15(), hashes.SHA256())
    rsa_record = {
        "approval_hash": approval_hash,
        "webauthn_proof": {
            "challenge": challenge,
            "challenge_nonce": nonce_b64,
            "challenge_binding": "sha256(nonce:approval_hash)",
            "approval_hash": approval_hash,
            "authenticator_data": _b64u(auth_data),
            "client_data_json": _b64u(client_data),
            "signature": _b64u(sig),
        },
    }
    ok, msg = verify_local_webauthn_cosign(rsa_record, [rsa_spki])
    assert ok is True
    assert "rsa" in msg.lower()
