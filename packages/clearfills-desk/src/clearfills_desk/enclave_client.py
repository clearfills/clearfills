"""Privilege-separated enclave & Unix-socket firewall client for ClearFills Desk OS.

Eliminates the Same-UID Ed25519 private-key threat (`EXECUTION_THREAT_MODEL.md`):
Instead of loading `authority_ed25519.pem` inside the coding agent's process/UID,
`DeskRuntime` delegates `propose()` and `dispatch_check()` over either:
  - A local `AF_UNIX` domain socket (`unix:///var/run/clearfills/signer.sock`)
    owned by a separate `clearfills-signer` OS user, or
  - A dedicated remote enclave daemon (`http://` or `https://`, e.g. Fly/Tailscale
    or AWS Nitro Enclave).

Uses 100% Python stdlib (`socket` + `http.client`) with zero extra dependencies.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Union
from urllib.parse import urlsplit

from clearfills_firewall import (
    KillSwitchState,
    PortfolioSnapshot,
    RiskDecision,
    SignedAttestation,
    TradeProposal,
    canonical_order_hash,
)
from clearfills_firewall.server import AuditVerifyResponse, DispatchCheckResponse

TransportResult = Union[dict[str, Any], tuple[int, dict[str, Any]]]
TransportCallable = Callable[[str, str, Optional[dict[str, Any]]], TransportResult]

_PROPOSE_SUFFIXES: tuple[str, ...] = (
    "/v1/firewall/propose",
    "/api/v1/firewall/propose",
    "/v1/propose",
)
_DISPATCH_SUFFIXES: tuple[str, ...] = (
    "/v1/firewall/dispatch-check",
    "/api/v1/firewall/dispatch-check",
    "/v1/dispatch-check",
)
_KILLSWITCH_STATUS_SUFFIXES: tuple[str, ...] = (
    "/v1/firewall/killswitch/status",
    "/api/v1/firewall/killswitch/status",
    "/v1/killswitch/status",
)
_AUDIT_VERIFY_SUFFIXES: tuple[str, ...] = (
    "/v1/firewall/audit/verify",
    "/api/v1/firewall/audit",
    "/v1/audit/verify",
)


class EnclaveClientError(RuntimeError):
    """Raised when communication with the remote signer enclave fails."""

    def __init__(self, message: str, *, status_code: Optional[int] = None) -> None:
        self.status_code = status_code
        super().__init__(message)


class _UnixHTTPConnection(http.client.HTTPConnection):
    """Stdlib HTTP/1.1 connection routed over an `AF_UNIX` stream socket."""

    def __init__(
        self,
        socket_path: str,
        timeout: float = 10.0,
        socket_factory: Optional[Callable[[str], socket.socket]] = None,
    ) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path
        self._socket_factory = socket_factory

    def connect(self) -> None:
        if self._socket_factory is not None:
            sock = self._socket_factory(self._socket_path)
            if self.timeout is not None:
                sock.settimeout(float(self.timeout))
            self.sock = sock
            return
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            sock.settimeout(float(self.timeout))
        try:
            sock.connect(self._socket_path)
        except Exception:
            sock.close()
            raise
        self.sock = sock


class _RemoteKillSwitchProxy:
    """Read-only kill-switch status proxy for MCP inspection in remote-enclave mode."""

    def __init__(self, client: "RemoteEnclaveFirewallClient") -> None:
        self._client = client

    def status(self) -> KillSwitchState:
        status_code, data = self._client._request_with_fallback(
            "GET",
            _KILLSWITCH_STATUS_SUFFIXES,
            None,
        )
        if status_code != 200:
            raise EnclaveClientError(
                f"Remote enclave killswitch status failed (HTTP {status_code}): {data.get('detail') or data}",
                status_code=status_code,
            )
        if "updated_at" not in data:
            data = {**data, "updated_at": datetime.now(timezone.utc).isoformat()}
        return KillSwitchState.model_validate(data)


class RemoteEnclaveFirewallClient:
    """Privilege-separated client for `clearfills-firewall` over `unix://` or `http(s)://`."""

    def __init__(
        self,
        endpoint: str,
        *,
        auth_token: Optional[str] = None,
        timeout: float = 10.0,
        transport: Optional[TransportCallable] = None,
        unix_socket_factory: Optional[Callable[[str], socket.socket]] = None,
    ) -> None:
        cleaned = (endpoint or "").strip()
        if not cleaned:
            raise ValueError("remote_signer_endpoint must be a non-empty URL or unix:// socket URI.")

        if cleaned.startswith("unix://"):
            sock_path = cleaned[len("unix://") :].strip()
            if not sock_path:
                raise ValueError(f"Missing Unix socket path in endpoint {endpoint!r}.")
            self._scheme = "unix"
            self._socket_path: Optional[str] = sock_path
            self._host = "localhost"
            self._port: Optional[int] = None
            self._base_path = ""
        elif cleaned.startswith(("http://", "https://")):
            parsed = urlsplit(cleaned)
            if not parsed.hostname:
                raise ValueError(f"Missing hostname in remote_signer_endpoint {endpoint!r}.")
            self._scheme = parsed.scheme.lower()
            self._socket_path = None
            self._host = parsed.hostname
            self._port = parsed.port
            self._base_path = parsed.path.rstrip("/")
        else:
            raise ValueError(
                f"Unsupported remote_signer_endpoint {endpoint!r}; "
                "expected 'unix:///path/to/signer.sock', 'http://...', or 'https://...'."
            )

        self.endpoint = cleaned
        self._timeout = float(timeout)
        raw_token = auth_token if auth_token is not None else os.environ.get("CLEARFILLS_SIGNER_TOKEN", "")
        self._auth_token: Optional[str] = raw_token.strip() or None
        self._transport = transport
        self._unix_socket_factory = unix_socket_factory
        self._preferred_slot: Optional[int] = None
        self.kill_switch = _RemoteKillSwitchProxy(self)

    @property
    def socket_path(self) -> Optional[str]:
        return self._socket_path

    def _open_connection(self) -> http.client.HTTPConnection:
        if self._scheme == "unix":
            assert self._socket_path is not None
            return _UnixHTTPConnection(
                self._socket_path,
                timeout=self._timeout,
                socket_factory=self._unix_socket_factory,
            )
        if self._scheme == "https":
            return http.client.HTTPSConnection(
                self._host,
                self._port,
                timeout=self._timeout,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)

    def _raw_request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
    ) -> tuple[int, dict[str, Any]]:
        full_path = f"{self._base_path}{path}" if self._base_path else path
        if self._transport is not None:
            res = self._transport(method, full_path, body)
            if isinstance(res, tuple) and len(res) == 2 and isinstance(res[0], int):
                code, payload = res
                if not isinstance(payload, dict):
                    raise EnclaveClientError("Remote enclave transport returned non-dict payload.")
                return code, payload
            if isinstance(res, dict):
                return 200, res
            raise EnclaveClientError(
                f"Unsupported enclave transport return value: {type(res).__name__}"
            )

        encoded_body = (
            json.dumps(body, separators=(",", ":"), default=str).encode("utf-8")
            if body is not None
            else None
        )
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Connection": "close",
        }
        if encoded_body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(encoded_body))
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        conn = self._open_connection()
        try:
            conn.request(method, full_path, body=encoded_body, headers=headers)
            resp = conn.getresponse()
            status_code = int(resp.status)
            raw_bytes = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            raise EnclaveClientError(
                f"Failed communicating with remote signer enclave ({self.endpoint}): {exc}"
            ) from exc
        finally:
            try:
                conn.close()
            except Exception:
                pass

        if not raw_bytes:
            return status_code, {}

        raw_text = raw_bytes.decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            if 200 <= status_code < 300:
                raise EnclaveClientError(
                    f"Remote signer enclave returned invalid JSON (HTTP {status_code}).",
                    status_code=status_code,
                ) from exc
            return status_code, {"detail": raw_text}

        if not isinstance(parsed, dict):
            raise EnclaveClientError(
                f"Remote signer enclave returned unexpected JSON type {type(parsed).__name__}.",
                status_code=status_code,
            )
        return status_code, parsed

    def _ordered_candidates(self, suffixes: tuple[str, ...]) -> list[tuple[int, str]]:
        indexed = list(enumerate(suffixes))
        if self._preferred_slot is not None and 0 <= self._preferred_slot < len(indexed):
            preferred = indexed.pop(self._preferred_slot)
            indexed.insert(0, preferred)
        return indexed

    def _request_with_fallback(
        self,
        method: str,
        suffixes: tuple[str, ...],
        body: Optional[dict[str, Any]],
    ) -> tuple[int, dict[str, Any]]:
        last_detail = ""
        for slot_idx, suffix in self._ordered_candidates(suffixes):
            status_code, data = self._raw_request(method, suffix, body)
            if status_code == 404:
                last_detail = str(data.get("detail") or suffix)
                continue
            self._preferred_slot = slot_idx
            return status_code, data
        raise EnclaveClientError(
            f"Remote signer enclave ({self.endpoint}) returned HTTP 404 for {suffixes[0]} ({last_detail}).",
            status_code=404,
        )

    def propose(self, proposal: TradeProposal, portfolio: PortfolioSnapshot) -> RiskDecision:
        """Evaluate a trade proposal via the privilege-separated signer enclave."""
        payload = {
            "proposal": proposal.model_dump(mode="json"),
            "portfolio": portfolio.model_dump(mode="json"),
        }
        status_code, data = self._request_with_fallback("POST", _PROPOSE_SUFFIXES, payload)
        if status_code != 200:
            raise EnclaveClientError(
                f"Remote enclave propose failed (HTTP {status_code}): {data.get('detail') or data}",
                status_code=status_code,
            )
        decision_raw = data["decision"] if isinstance(data.get("decision"), dict) else data
        return RiskDecision.model_validate(decision_raw)

    def dispatch_check(
        self,
        attestation: SignedAttestation,
        proposal: TradeProposal,
    ) -> DispatchCheckResponse:
        """Verify and atomically consume a single-use Ed25519 attestation via the signer enclave."""
        payload = {
            "attestation": attestation.model_dump(mode="json"),
            "proposal": proposal.model_dump(mode="json"),
        }
        status_code, data = self._request_with_fallback("POST", _DISPATCH_SUFFIXES, payload)
        computed_hash = canonical_order_hash(proposal)

        if status_code == 200:
            allowed = data.get("allowed") is True
            return DispatchCheckResponse(
                allowed=allowed,
                reason=str(data.get("reason") or ("OK" if allowed else "REJECTED")),
                attestation_id=str(data.get("attestation_id") or attestation.attestation_id),
                proposal_id=str(data.get("proposal_id") or proposal.proposal_id),
                order_hash=str(data.get("order_hash") or computed_hash),
            )

        if status_code in {400, 401, 403, 409, 422}:
            reason = str(data.get("reason") or data.get("detail") or f"HTTP_{status_code}")
            return DispatchCheckResponse(
                allowed=False,
                reason=reason,
                attestation_id=str(data.get("attestation_id") or attestation.attestation_id),
                proposal_id=str(data.get("proposal_id") or proposal.proposal_id),
                order_hash=str(data.get("order_hash") or computed_hash),
            )

        raise EnclaveClientError(
            f"Remote enclave dispatch_check failed (HTTP {status_code}): {data.get('detail') or data}",
            status_code=status_code,
        )

    def verify_audit(self) -> AuditVerifyResponse:
        """Verify remote enclave SHA-256 audit chain integrity."""
        status_code, data = self._request_with_fallback("GET", _AUDIT_VERIFY_SUFFIXES, None)
        if status_code != 200:
            raise EnclaveClientError(
                f"Remote enclave audit verification failed (HTTP {status_code}): {data.get('detail') or data}",
                status_code=status_code,
            )
        valid_flag = data.get("valid") if "valid" in data else data.get("chain_valid", False)
        return AuditVerifyResponse(
            valid=bool(valid_flag),
            error=data.get("error"),
            entry_count=int(data.get("entry_count") or 0),
        )
