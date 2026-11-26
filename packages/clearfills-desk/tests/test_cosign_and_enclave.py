"""Tests for local WebAuthn hardware co-signature verification & Unix-socket/HTTP enclave client."""

from __future__ import annotations

import base64
import errno
import hashlib
import http.server
import json
import socket
import socketserver
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from clearfills_desk import (
    ApprovalWorker,
    DeskConfig,
    DeskRuntime,
    EnclaveClientError,
    IBKRConnectionConfig,
    IBKRExecutionAdapter,
    LiveExecutionSafetyError,
    RemoteEnclaveFirewallClient,
    compute_approval_hash,
    verify_operator_passkey_cosignature,
)
from clearfills_firewall import (
    FirewallService,
    OrderType,
    PortfolioSnapshot,
    RiskPolicy,
    Side,
    TradeProposal,
    default_allocation_sleeves,
)

_ET = ZoneInfo("America/New_York")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _generate_p256_spki() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, _b64u(der)


def _sign_touchid_bundle(
    priv: ec.EllipticCurvePrivateKey,
    *,
    challenge_nonce: str,
    approval_hash: str,
    up_bit: bool = True,
    ceremony_type: str = "webauthn.get",
    rp_id: str = "clearfills.com",
    include_bundle_hash: bool = True,
) -> dict[str, Any]:
    challenge = _b64u(hashlib.sha256(f"{challenge_nonce}:{approval_hash}".encode("utf-8")).digest())
    flags = 0x05 if up_bit else 0x00
    auth_data = hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([flags]) + (1).to_bytes(4, "big")
    client_data = json.dumps(
        {
            "type": ceremony_type,
            "challenge": challenge,
            "origin": f"https://{rp_id}",
        }
    ).encode("utf-8")
    sig = priv.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    bundle: dict[str, Any] = {
        "credential_id": "cred_touchid_macbook_pro",
        "challenge": challenge,
        "challenge_nonce": challenge_nonce,
        "challenge_binding": "sha256(nonce:approval_hash)",
        "authenticator_data": _b64u(auth_data),
        "client_data_json": _b64u(client_data),
        "signature": _b64u(sig),
    }
    if include_bundle_hash:
        bundle["approval_hash"] = approval_hash
    return bundle


class _MockIB:
    """Deterministic offline IBKR mock for worker & enclave dispatch tests."""

    def __init__(self, *, bid: float = 100.20, ask: float = 100.25, last: float = 100.22) -> None:
        self._connected = False
        self.bid = bid
        self.ask = ask
        self.last = last
        self.placed: list[tuple[Any, Any]] = []
        self.quote_calls: list[Any] = []
        self._next_oid = 4101

    def isConnected(self) -> bool:
        return self._connected

    def connect(self, host: str, port: int, clientId: int = 1, readonly: bool = False) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def managedAccounts(self) -> list[str]:
        return ["DU1234567"]

    def accountSummary(self, account: str = "") -> list[Any]:
        return [
            SimpleNamespace(tag="NetLiquidation", currency="USD", value="500000.00"),
            SimpleNamespace(tag="BuyingPower", currency="USD", value="1000000.00"),
            SimpleNamespace(tag="SettledCash", currency="USD", value="300000.00"),
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


def _make_pinned_adapter(
    tmp_path: Path,
    *,
    operator_passkey_spki_b64: list[str],
    remote_signer_endpoint: str | None = None,
) -> tuple[IBKRExecutionAdapter, _MockIB, Path]:
    state_dir = tmp_path / "agent_desk_state"
    cfg = DeskConfig(
        desk_id="pinned-desk-01",
        desk_name="Pinned CoSign & Enclave Desk",
        execution_mode="paper",
        remote_signer_endpoint=remote_signer_endpoint,
        operator_passkey_spki_b64=operator_passkey_spki_b64,
        ibkr=IBKRConnectionConfig(
            host="127.0.0.1",
            port=4002,
            account_id="DU1234567",
            allow_live=False,
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
    runtime = DeskRuntime(cfg, state_dir=state_dir)
    mock_ib = _MockIB()
    adapter = IBKRExecutionAdapter(runtime, ib_client=mock_ib, env={})
    return adapter, mock_ib, state_dir


def _build_canonical_cloud_approval(
    *,
    approval_id: str = "apr_touchid_001",
    symbol: str = "SGOV",
    side: str = "BUY",
    quantity: float = 300.0,
    limit_price: float = 100.25,
) -> dict[str, Any]:
    created_at = datetime(2026, 11, 24, 15, 30, 0, tzinfo=timezone.utc)
    rec: dict[str, Any] = {
        "approval_id": approval_id,
        "status": "approved",
        "symbol": symbol,
        "side": side,
        "quantity": quantity,
        "limit_price": limit_price,
        "stop_price": None,
        "target_price": None,
        "order_type": "LIMIT",
        "notional_usd": round(quantity * limit_price, 2),
        "sleeve": "cash_management",
        "venue": "ibkr",
        "attestation_id": "att_preview_expired",
        "agent_id": "allocator-agent",
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    rec["approval_hash"] = compute_approval_hash(rec)
    return rec


def _cloud_transport_for(records: list[dict[str, Any]], reports: list[tuple[str, dict[str, Any]]]):
    queue = list(records)

    def transport(method: str, path: str, body: Any) -> Any:
        if method == "POST" and path == "/api/v1/cloud/worker/heartbeat":
            return {"ok": True}
        if method == "GET" and path == "/api/v1/cloud/approvals?status=approved":
            batch = list(queue)
            queue.clear()
            return batch
        if method == "POST" and path.endswith("/claim"):
            return {"claimed": True}
        if method == "POST" and path.endswith("/executed"):
            reports.append((path, body))
            return {"ok": True}
        raise AssertionError(f"Unexpected cloud call: {method} {path}")

    return transport


def test_pinned_operator_passkey_accepts_valid_p256_cosignature_and_blocks_replay(tmp_path: Path) -> None:
    priv, spki_b64 = _generate_p256_spki()
    adapter, mock_ib, _ = _make_pinned_adapter(tmp_path, operator_passkey_spki_b64=[spki_b64])

    rec = _build_canonical_cloud_approval(approval_id="apr_hw_valid_01")
    nonce = _b64u(b"touchid_nonce_000000000001")
    rec["passkey_assertion_bundle"] = _sign_touchid_bundle(
        priv,
        challenge_nonce=nonce,
        approval_hash=rec["approval_hash"],
    )

    # Second approval attempts to replay the exact same Touch ID assertion bundle
    replay_rec = dict(rec)
    replay_rec["approval_id"] = "apr_hw_replay_02"
    # Even if approval_hash were not recomputed on minimal record, worker tracks used challenges
    minimal_replay = {
        "approval_id": "apr_hw_replay_02",
        "status": "approved",
        "venue": "ibkr",
        "symbol": "SGOV",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 300.0,
        "limit_price": 100.25,
        "approval_hash": rec["approval_hash"],
        "passkey_assertion_bundle": rec["passkey_assertion_bundle"],
    }

    reports: list[tuple[str, dict[str, Any]]] = []
    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        cloud_transport=_cloud_transport_for([rec, minimal_replay], reports),
    )

    outcomes = worker.poll_once()
    assert len(outcomes) == 2

    assert outcomes[0]["approval_id"] == "apr_hw_valid_01"
    assert outcomes[0]["status"] == "submitted"
    assert outcomes[0]["broker_order_id"] == "4101"

    assert outcomes[1]["approval_id"] == "apr_hw_replay_02"
    assert outcomes[1]["status"] == "cosign_rejected"
    assert "Operator hardware passkey co-signature verification failed" in outcomes[1]["detail"]

    # Only the legitimate first order reached IBKR
    assert len(mock_ib.placed) == 1
    assert reports[0][1]["status"] == "submitted"
    assert reports[1][1]["status"] == "cosign_rejected"


def test_pinned_operator_passkey_blocks_missing_forged_and_tampered_cloud_approvals(tmp_path: Path) -> None:
    operator_priv, operator_spki_b64 = _generate_p256_spki()
    attacker_priv, _ = _generate_p256_spki()
    adapter, mock_ib, _ = _make_pinned_adapter(
        tmp_path,
        operator_passkey_spki_b64=[operator_spki_b64],
    )

    # 1. Missing passkey_assertion_bundle (compromised Cloud API flipped status='approved' directly)
    missing_rec = _build_canonical_cloud_approval(approval_id="apr_missing_bundle")

    # 2. Forged signature signed by attacker's WebAuthn key (enrolled in compromised Cloud DB, not pinned locally)
    forged_rec = _build_canonical_cloud_approval(approval_id="apr_forged_sig")
    forged_rec["passkey_assertion_bundle"] = _sign_touchid_bundle(
        attacker_priv,
        challenge_nonce=_b64u(b"attacker_nonce_00000000002"),
        approval_hash=forged_rec["approval_hash"],
    )

    # 3. Tampered order legs WITHOUT updating approval_hash (Cloud DB mutated 300 SGOV -> 3000 NVDA)
    tampered_legs_rec = _build_canonical_cloud_approval(approval_id="apr_tampered_legs")
    tampered_legs_rec["passkey_assertion_bundle"] = _sign_touchid_bundle(
        operator_priv,
        challenge_nonce=_b64u(b"operator_nonce_00000000003"),
        approval_hash=tampered_legs_rec["approval_hash"],
    )
    tampered_legs_rec["symbol"] = "NVDA"
    tampered_legs_rec["quantity"] = 3000.0

    # 4. Tampered order legs WITH recomputed record approval_hash (mismatches signed sha256(nonce:approval_hash))
    tampered_hash_rec = _build_canonical_cloud_approval(approval_id="apr_tampered_hash")
    orig_bundle = _sign_touchid_bundle(
        operator_priv,
        challenge_nonce=_b64u(b"operator_nonce_00000000004"),
        approval_hash=tampered_hash_rec["approval_hash"],
        include_bundle_hash=False,
    )
    tampered_hash_rec["quantity"] = 450.0
    tampered_hash_rec["notional_usd"] = round(450.0 * 100.25, 2)
    tampered_hash_rec["approval_hash"] = compute_approval_hash(tampered_hash_rec)
    tampered_hash_rec["passkey_assertion_bundle"] = orig_bundle

    reports: list[tuple[str, dict[str, Any]]] = []
    worker = ApprovalWorker(
        adapter=adapter,
        api_key="cf_test_key",
        cloud_transport=_cloud_transport_for(
            [missing_rec, forged_rec, tampered_legs_rec, tampered_hash_rec],
            reports,
        ),
    )

    outcomes = worker.poll_once()
    assert len(outcomes) == 4
    for out in outcomes:
        assert out["status"] == "cosign_rejected"
        assert out["detail"].startswith("Operator hardware passkey co-signature verification failed")

    # Zero quotes fetched and zero orders submitted to IBKR
    assert len(mock_ib.quote_calls) == 0
    assert len(mock_ib.placed) == 0
    assert len(reports) == 4
    assert all(r[1]["status"] == "cosign_rejected" for r in reports)


def test_verify_operator_passkey_cosignature_up_bit_ceremony_rsa_and_unpinned_passthrough() -> None:
    # Empty trusted_spki_keys_b64 fails closed (no unpinned passthrough)
    ok, reason = verify_operator_passkey_cosignature({"approval_id": "apr_none"}, [])
    assert ok is False
    assert "pinned" in reason.lower()

    priv, spki_b64 = _generate_p256_spki()
    nonce = _b64u(b"edge_case_nonce_0000000001")
    approval_hash = hashlib.sha256(b"SGOV:BUY:100:100.25").hexdigest()

    # User Present bit cleared -> rejected
    no_up = _sign_touchid_bundle(priv, challenge_nonce=nonce, approval_hash=approval_hash, up_bit=False)
    ok, reason = verify_operator_passkey_cosignature(
        {"approval_hash": approval_hash, "passkey_assertion_bundle": no_up},
        [spki_b64],
    )
    assert ok is False
    assert "User Present" in reason

    # Wrong WebAuthn ceremony type -> rejected
    bad_type = _sign_touchid_bundle(
        priv,
        challenge_nonce=nonce,
        approval_hash=approval_hash,
        ceremony_type="webauthn.create",
    )
    ok, reason = verify_operator_passkey_cosignature(
        {"approval_hash": approval_hash, "passkey_assertion_bundle": bad_type},
        [spki_b64],
    )
    assert ok is False
    assert "webauthn.get" in reason

    # RSA-2048 PKCS1v15 SHA-256 YubiKey with standard base64 SPKI + `passkey_assertion` fallback field
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_spki_std_b64 = base64.b64encode(
        rsa_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")
    challenge = _b64u(hashlib.sha256(f"{nonce}:{approval_hash}".encode("utf-8")).digest())
    auth_data = hashlib.sha256(b"clearfills.com").digest() + bytes([0x05]) + (7).to_bytes(4, "big")
    client_data = json.dumps(
        {"type": "webauthn.get", "challenge": challenge, "origin": "https://clearfills.com"}
    ).encode("utf-8")
    rsa_sig = rsa_priv.sign(
        auth_data + hashlib.sha256(client_data).digest(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    ok, reason = verify_operator_passkey_cosignature(
        {
            "approval_hash": approval_hash,
            "passkey_assertion": {
                "challenge": challenge,
                "challenge_nonce": nonce,
                "authenticator_data": _b64u(auth_data),
                "client_data_json": _b64u(client_data),
                "signature": base64.b64encode(rsa_sig).decode("ascii"),
            },
        },
        [rsa_spki_std_b64],
    )
    assert ok is True
    assert "rsa" in reason.lower()


class _UnixSignerServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def _start_unix_enclave_daemon(
    sock_path: Path,
    enclave_service: FirewallService,
) -> tuple[_UnixSignerServer, threading.Thread, Any]:
    """Spin up an isolated stdlib UnixStreamServer speaking the enclave firewall JSON protocol."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def address_string(self) -> str:
            return "unix-client"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/v1/firewall/killswitch/status":
                self._send_json(200, enclave_service.kill_switch.status().model_dump(mode="json"))
                return
            if self.path == "/v1/firewall/audit/verify":
                self._send_json(200, enclave_service.verify_audit().model_dump(mode="json"))
                return
            self._send_json(404, {"detail": "Not Found"})

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
            if self.path == "/v1/firewall/propose":
                prop = TradeProposal.model_validate(body["proposal"])
                pf = PortfolioSnapshot.model_validate(body["portfolio"])
                decision = enclave_service.propose(proposal=prop, portfolio=pf)
                self._send_json(200, decision.model_dump(mode="json"))
                return
            if self.path == "/v1/firewall/dispatch-check":
                from clearfills_firewall import SignedAttestation

                att = SignedAttestation.model_validate(body["attestation"])
                prop = TradeProposal.model_validate(body["proposal"])
                res = enclave_service.dispatch_check(attestation=att, proposal=prop)
                self._send_json(200 if res.allowed else 403, res.model_dump(mode="json"))
                return
            self._send_json(404, {"detail": "Not Found"})

    server = _UnixSignerServer(str(sock_path), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Probe whether the current execution environment allows AF_UNIX connect(2).
    # Standard macOS/Linux shells allow connect(2) directly against UnixStreamServer;
    # restricted macOS Seatbelt test sandboxes deny connect(2) with EPERM while allowing
    # AF_UNIX socketpair(), which exercises the exact same HTTP/1.1 + AF_UNIX wire stack.
    socket_factory = None
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(str(sock_path))
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES):
            def _socketpair_factory(_target_path: str) -> socket.socket:
                client_sock, server_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

                def _serve_conn() -> None:
                    try:
                        _Handler(server_sock, ("unix", 0), server)
                    finally:
                        server_sock.close()

                threading.Thread(target=_serve_conn, daemon=True).start()
                return client_sock

            socket_factory = _socketpair_factory
        else:
            raise
    finally:
        probe.close()

    return server, thread, socket_factory


def test_unix_socket_enclave_creates_zero_local_pem_keys_and_evaluates_and_dispatches(
    tmp_path: Path,
) -> None:
    enclave_data_dir = tmp_path / "isolated_signer_uid_dir"
    agent_state_dir = tmp_path / "agent_shell_uid_dir"

    policy = RiskPolicy(
        max_risk_per_trade_pct=1.0,
        max_total_heat_pct=12.0,
        max_daily_loss_pct=2.0,
        max_order_notional_usd=50_000.0,
        require_stop_loss=True,
        max_entries_per_session=4,
        block_last_session_of_week=False,
        sleeves=default_allocation_sleeves(),
    )
    enclave_service = FirewallService.from_data_dir(
        data_dir=enclave_data_dir,
        policy=policy,
        initialize_armed=True,
        ttl_seconds=120,
    )
    assert (enclave_data_dir / "authority_ed25519.pem").exists()

    # Keep AF_UNIX socket path well below macOS 104-byte sockaddr_un limit
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="cf_enc_") as short_dir:
        sock_path = Path(short_dir) / "signer.sock"
        server, thread, socket_factory = _start_unix_enclave_daemon(sock_path, enclave_service)
        try:
            priv, spki_b64 = _generate_p256_spki()
            cfg = DeskConfig(
                desk_id="unix-enclave-desk",
                desk_name="Privilege-Separated Enclave Desk",
                execution_mode="paper",
                remote_signer_endpoint=f"unix://{sock_path}",
                operator_passkey_spki_b64=[spki_b64],
                ibkr=IBKRConnectionConfig(
                    host="127.0.0.1",
                    port=4002,
                    account_id="DU1234567",
                    allow_live=False,
                ),
                risk=policy,
            )
            enclave_client = (
                RemoteEnclaveFirewallClient(cfg.remote_signer_endpoint, unix_socket_factory=socket_factory)
                if socket_factory is not None and cfg.remote_signer_endpoint
                else None
            )
            rt = DeskRuntime(cfg, state_dir=agent_state_dir, enclave_client=enclave_client)

            # CRITICAL INVARIANT: Agent's local desk directory contains ZERO .pem private keys!
            assert list(agent_state_dir.rglob("*.pem")) == []
            assert not (agent_state_dir / "firewall").exists()

            tuesday_et = datetime(2026, 11, 24, 10, 30, tzinfo=_ET).astimezone(timezone.utc)
            proposal = TradeProposal(
                agent_id="strategist",
                venue="ibkr",
                symbol="NVDA",
                side=Side.BUY,
                order_type=OrderType.LIMIT,
                quantity=20.0,
                limit_price=135.0,
                stop_price=129.0,
                created_at=tuesday_et,
            )
            portfolio = PortfolioSnapshot(nav_usd=200_000.0, cash_usd=200_000.0, session_entries=1)

            decision = rt.evaluate_proposal(proposal=proposal, portfolio=portfolio)
            assert decision.approved is True
            assert decision.attestation is not None
            assert decision.attestation.key_id == enclave_service.authority.key_id

            # First dispatch succeeds over the Unix socket; replay is rejected (HTTP 403 -> False)
            assert rt.verify_dispatch(decision.attestation, proposal) is True
            assert rt.verify_dispatch(decision.attestation, proposal) is False

            # Post-attestation order tampering is rejected by the enclave
            decision2 = rt.evaluate_proposal(proposal=proposal, portfolio=portfolio)
            assert decision2.attestation is not None
            tampered_proposal = proposal.model_copy(update={"quantity": 200.0})
            mock_ib = _MockIB()
            adapter = IBKRExecutionAdapter(rt, ib_client=mock_ib, env={})
            with pytest.raises(LiveExecutionSafetyError, match="Dispatch rejected"):
                adapter.submit_attested_order(tampered_proposal, decision2.attestation)
            assert len(mock_ib.placed) == 0

            # Full end-to-end ApprovalWorker with BOTH pinned Touch ID co-sign AND Unix-socket enclave
            rec = _build_canonical_cloud_approval(approval_id="apr_e2e_enclave_cosign")
            rec["passkey_assertion_bundle"] = _sign_touchid_bundle(
                priv,
                challenge_nonce=_b64u(b"e2e_enclave_nonce_00000001"),
                approval_hash=rec["approval_hash"],
            )
            reports: list[tuple[str, dict[str, Any]]] = []
            worker = ApprovalWorker(
                adapter=adapter,
                api_key="cf_test_key",
                cloud_transport=_cloud_transport_for([rec], reports),
            )
            outcomes = worker.poll_once()
            assert len(outcomes) == 1
            assert outcomes[0]["status"] == "submitted"
            assert len(mock_ib.placed) == 1

            # Audit chain & kill-switch inspection work over Unix socket too, still zero local .pem files
            assert rt.firewall.verify_audit().valid is True
            assert rt.firewall.kill_switch.status().tripped is False
            assert list(agent_state_dir.rglob("*.pem")) == []
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)


def test_remote_enclave_client_http_fallback_and_fail_closed_errors(tmp_path: Path) -> None:
    enclave_service = FirewallService.from_data_dir(
        data_dir=tmp_path / "http_enclave",
        initialize_armed=True,
    )
    seen_paths: list[str] = []

    def api_prefix_transport(method: str, path: str, body: dict[str, Any] | None):
        seen_paths.append(path)
        # Simulate ClearFills Cloud /api/v1/firewall/* mount returning wrapped FirewallProposeResponse
        if path == "/api/v1/firewall/propose" and body is not None:
            dec = enclave_service.propose(
                proposal=TradeProposal.model_validate(body["proposal"]),
                portfolio=PortfolioSnapshot.model_validate(body["portfolio"]),
            )
            return 200, {"decision": dec.model_dump(mode="json"), "approved": dec.approved}
        if path == "/api/v1/firewall/dispatch-check" and body is not None:
            from clearfills_firewall import SignedAttestation

            res = enclave_service.dispatch_check(
                attestation=SignedAttestation.model_validate(body["attestation"]),
                proposal=TradeProposal.model_validate(body["proposal"]),
            )
            return (200 if res.allowed else 403), res.model_dump(mode="json")
        return 404, {"detail": "Not Found"}

    client = RemoteEnclaveFirewallClient(
        "http://100.64.0.10:8080",
        auth_token="enclave_secret_tok",
        transport=api_prefix_transport,
    )
    prop = TradeProposal(
        agent_id="strategist",
        venue="ibkr",
        symbol="SGOV",
        side=Side.BUY,
        order_type=OrderType.LIMIT,
        quantity=50.0,
        limit_price=100.25,
        stop_price=99.50,
        created_at=datetime(2026, 11, 24, 10, 30, tzinfo=_ET).astimezone(timezone.utc),
    )
    pf = PortfolioSnapshot(nav_usd=100_000.0, cash_usd=100_000.0)
    dec = client.propose(prop, pf)
    assert dec.approved is True
    assert dec.attestation is not None
    # First call tried /v1/firewall/propose (404) then discovered /api/v1/firewall/propose (200)
    assert seen_paths[:2] == ["/v1/firewall/propose", "/api/v1/firewall/propose"]

    # Subsequent call uses cached /api/v1/firewall/* slot directly with zero 404 retry
    disp = client.dispatch_check(dec.attestation, prop)
    assert disp.allowed is True
    assert seen_paths[2] == "/api/v1/firewall/dispatch-check"

    # Invalid endpoint scheme rejected at config & client boundary
    with pytest.raises(ValueError, match="remote_signer_endpoint"):
        DeskConfig(desk_id="bad", desk_name="Bad", remote_signer_endpoint="ftp://bad-host")

    # Missing Unix socket fails closed with EnclaveClientError
    dead_client = RemoteEnclaveFirewallClient("unix:///tmp/cf_nonexistent_enclave_99999.sock")
    with pytest.raises(EnclaveClientError):
        dead_client.propose(prop, pf)
