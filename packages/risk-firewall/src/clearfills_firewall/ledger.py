"""Tamper-evident append-only SHA-256 hash-chained & Ed25519-signed JSONL audit ledger.

Uses RFC 8785 (JCS) canonical JSON serialization for entry hashing, optional Ed25519
per-entry signatures, and checkpoint verification that detects tail truncation as well
as in-place tampering.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from ._locks import file_lock
from .canonical import canonical_json_bytes
from .models import AuditEntry, utc_now

GENESIS_HASH = "0" * 64


def _compute_entry_hash(
    *,
    seq: int,
    timestamp: datetime,
    event_type: str,
    actor: str,
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    canonical_bytes = canonical_json_bytes(
        {
            "seq": seq,
            "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
            "event_type": event_type,
            "actor": actor,
            "payload": payload,
            "prev_hash": prev_hash,
        }
    )
    return hashlib.sha256(canonical_bytes).hexdigest()


def _load_optional_private_key(
    key: Optional[Ed25519PrivateKey | bytes | str],
) -> Optional[Ed25519PrivateKey]:
    if key is None:
        return None
    if isinstance(key, Ed25519PrivateKey):
        return key
    raw = key.encode("utf-8") if isinstance(key, str) else key
    loaded = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519 private key, got {type(loaded).__name__}")
    return loaded


def _load_optional_public_key(
    key: Optional[Ed25519PublicKey | bytes | str],
) -> Optional[Ed25519PublicKey]:
    if key is None:
        return None
    if isinstance(key, Ed25519PublicKey):
        return key
    raw = key.encode("utf-8") if isinstance(key, str) else key
    loaded = serialization.load_pem_public_key(raw)
    if not isinstance(loaded, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519 public key, got {type(loaded).__name__}")
    return loaded


def _key_id_for_public_key(pub: Ed25519PublicKey) -> str:
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519_{hashlib.sha256(pub_bytes).hexdigest()[:16]}"


class AuditLedger:
    """Append-only JSONL audit ledger with RFC 8785 SHA-256 hash chaining & Ed25519 signatures."""

    def __init__(
        self,
        ledger_path: str | Path,
        *,
        private_key: Optional[Ed25519PrivateKey | bytes | str] = None,
    ) -> None:
        self._path = Path(ledger_path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._private_key: Optional[Ed25519PrivateKey] = _load_optional_private_key(private_key)
        self._public_key: Optional[Ed25519PublicKey] = (
            self._private_key.public_key() if self._private_key is not None else None
        )
        self._signer_key_id: Optional[str] = (
            _key_id_for_public_key(self._public_key) if self._public_key is not None else None
        )

    @property
    def ledger_path(self) -> Path:
        return self._path

    def public_key_pem(self) -> Optional[str]:
        if self._public_key is None:
            return None
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def append(
        self,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        timestamp: Optional[datetime] = None,
    ) -> AuditEntry:
        """Append a new hash-chained (and optionally Ed25519-signed) entry to the JSONL ledger."""
        event_clean = event_type.strip()
        actor_clean = actor.strip()
        if not event_clean or not actor_clean:
            raise ValueError("event_type and actor must be non-empty")

        ts = (timestamp or utc_now()).astimezone(timezone.utc)
        # Round-trip payload through JSON so hashes match deserialized values deterministically
        normalized_payload: dict[str, Any] = json.loads(json.dumps(payload, default=str))

        with self._lock, file_lock(self._path):
            seq, prev_hash = self._get_tail_state()
            next_seq = seq + 1
            entry_hash = _compute_entry_hash(
                seq=next_seq,
                timestamp=ts,
                event_type=event_clean,
                actor=actor_clean,
                payload=normalized_payload,
                prev_hash=prev_hash,
            )
            entry_signature: Optional[str] = None
            signer_key_id: Optional[str] = None
            if self._private_key is not None:
                sig_bytes = self._private_key.sign(entry_hash.encode("ascii"))
                entry_signature = base64.b64encode(sig_bytes).decode("ascii")
                signer_key_id = self._signer_key_id

            entry = AuditEntry(
                seq=next_seq,
                timestamp=ts,
                event_type=event_clean,
                actor=actor_clean,
                payload=normalized_payload,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                entry_signature=entry_signature,
                signer_key_id=signer_key_id,
            )
            line = entry.model_dump_json() + "\n"
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def get_checkpoint(self) -> dict[str, Any]:
        """Return the current ledger head checkpoint (`seq_no`, `head_hash`, `head_sig`)."""
        with self._lock:
            last = self._get_tail_entry()
            if last is None:
                return {
                    "seq_no": 0,
                    "head_hash": GENESIS_HASH,
                    "head_sig": None,
                    "signer_key_id": None,
                }
            return {
                "seq_no": last.seq,
                "head_hash": last.entry_hash,
                "head_sig": last.entry_signature,
                "signer_key_id": last.signer_key_id,
            }

    def verify_chain(
        self,
        expected_min_seq: int = 0,
        expected_checkpoint_hash: Optional[str] = None,
        public_key_pem: Optional[bytes | str | Ed25519PublicKey] = None,
    ) -> tuple[bool, Optional[str], int]:
        """Verify entire SHA-256 hash chain from genesis to tip, signatures, and checkpoints.

        Fails closed on:
        - Modified entry content / hash mismatch
        - Broken `prev_hash` link or sequence gap
        - Invalid or missing Ed25519 signature (when `public_key_pem` is supplied)
        - Tail truncation (`entry_count < expected_min_seq`)
        - Checkpoint hash mismatch (`expected_checkpoint_hash`)

        Returns `(valid, error_message, verified_entry_count)`.
        """
        require_signatures = public_key_pem is not None
        try:
            verify_pub: Optional[Ed25519PublicKey] = (
                _load_optional_public_key(public_key_pem)
                if public_key_pem is not None
                else self._public_key
            )
        except (ValueError, TypeError) as exc:
            return False, f"Invalid verification public key: {exc}", 0

        with self._lock:
            if not self._path.exists():
                if expected_min_seq > 0:
                    return (
                        False,
                        f"Tail truncation detected: ledger file missing (expected at least {expected_min_seq} entries)",
                        0,
                    )
                if expected_checkpoint_hash is not None and expected_checkpoint_hash != GENESIS_HASH:
                    return (
                        False,
                        f"Checkpoint hash mismatch: ledger file missing (expected {expected_checkpoint_hash})",
                        0,
                    )
                return True, None, 0

            expected_prev = GENESIS_HASH
            expected_seq = 1
            count = 0
            checkpoint_seen_hash: Optional[str] = None
            last_hash = GENESIS_HASH

            try:
                lines = self._path.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                return False, f"Failed to read ledger file: {exc}", 0

            for line_no, raw_line in enumerate(lines, start=1):
                if not raw_line.strip():
                    return False, f"Blank or truncated line at line {line_no}", count
                try:
                    data = json.loads(raw_line)
                    entry = AuditEntry.model_validate(data)
                except (json.JSONDecodeError, ValidationError) as exc:
                    return False, f"Malformed entry at line {line_no}: {exc}", count

                if entry.seq != expected_seq:
                    return (
                        False,
                        f"Sequence mismatch at line {line_no}: expected {expected_seq}, got {entry.seq}",
                        count,
                    )

                if entry.prev_hash != expected_prev:
                    return (
                        False,
                        f"Broken prev_hash link at seq {entry.seq} (line {line_no})",
                        count,
                    )

                try:
                    recomputed = _compute_entry_hash(
                        seq=entry.seq,
                        timestamp=entry.timestamp,
                        event_type=entry.event_type,
                        actor=entry.actor,
                        payload=entry.payload,
                        prev_hash=entry.prev_hash,
                    )
                except (ValueError, TypeError) as exc:
                    return (
                        False,
                        f"Canonical hash computation failed at seq {entry.seq} (line {line_no}): {exc}",
                        count,
                    )

                if entry.entry_hash != recomputed:
                    return (
                        False,
                        f"Entry hash tamper detected at seq {entry.seq} (line {line_no})",
                        count,
                    )

                if require_signatures:
                    if not entry.entry_signature:
                        return (
                            False,
                            f"Missing Ed25519 entry_signature at seq {entry.seq} (line {line_no})",
                            count,
                        )
                    assert verify_pub is not None
                    try:
                        raw_sig = base64.b64decode(entry.entry_signature.encode("ascii"), validate=True)
                        verify_pub.verify(raw_sig, entry.entry_hash.encode("ascii"))
                    except (InvalidSignature, ValueError):
                        return (
                            False,
                            f"Invalid Ed25519 signature at seq {entry.seq} (line {line_no})",
                            count,
                        )
                elif verify_pub is not None and entry.entry_signature is not None:
                    try:
                        raw_sig = base64.b64decode(entry.entry_signature.encode("ascii"), validate=True)
                        verify_pub.verify(raw_sig, entry.entry_hash.encode("ascii"))
                    except (InvalidSignature, ValueError):
                        return (
                            False,
                            f"Invalid Ed25519 signature at seq {entry.seq} (line {line_no})",
                            count,
                        )

                if expected_min_seq > 0 and entry.seq == expected_min_seq:
                    checkpoint_seen_hash = entry.entry_hash

                expected_prev = entry.entry_hash
                last_hash = entry.entry_hash
                expected_seq += 1
                count += 1

            if count < expected_min_seq:
                return (
                    False,
                    f"Tail truncation detected: ledger has {count} entries, expected at least {expected_min_seq}",
                    count,
                )

            if expected_checkpoint_hash is not None:
                compare_hash = checkpoint_seen_hash if expected_min_seq > 0 else last_hash
                if compare_hash != expected_checkpoint_hash:
                    return (
                        False,
                        f"Checkpoint hash mismatch at seq {expected_min_seq or count}: expected {expected_checkpoint_hash}, got {compare_hash}",
                        count,
                    )

            return True, None, count

    def read_entries(self, limit: Optional[int] = None) -> list[AuditEntry]:
        """Read audit entries (optionally returning the most recent `limit` entries)."""
        with self._lock:
            if not self._path.exists():
                return []
            lines = [ln for ln in self._path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if limit is not None and limit > 0:
                lines = lines[-limit:]
            return [AuditEntry.model_validate_json(ln) for ln in lines]

    def _get_tail_entry(self) -> Optional[AuditEntry]:
        if not self._path.exists():
            return None
        size = self._path.stat().st_size
        if size == 0:
            return None
        with self._path.open("rb") as fh:
            chunk_size = 8192
            pos = size
            buf = b""
            while pos > 0:
                read_len = min(chunk_size, pos)
                pos -= read_len
                fh.seek(pos)
                buf = fh.read(read_len) + buf
                lines = [ln for ln in buf.splitlines() if ln.strip()]
                if len(lines) >= 2 or pos == 0:
                    if not lines:
                        return None
                    return AuditEntry.model_validate_json(lines[-1].decode("utf-8"))
        return None

    def _get_tail_state(self) -> tuple[int, str]:
        last = self._get_tail_entry()
        if last is None:
            return 0, GENESIS_HASH
        return last.seq, last.entry_hash
