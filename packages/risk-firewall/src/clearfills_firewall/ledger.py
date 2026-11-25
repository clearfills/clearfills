"""Tamper-evident append-only SHA-256 hash-chained JSONL audit ledger."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import ValidationError

from ._locks import file_lock
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
    canonical = json.dumps(
        {
            "seq": seq,
            "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
            "event_type": event_type,
            "actor": actor,
            "payload": payload,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLedger:
    """Append-only JSONL audit ledger with SHA-256 hash chaining."""

    def __init__(self, ledger_path: str | Path) -> None:
        self._path = Path(ledger_path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def ledger_path(self) -> Path:
        return self._path

    def append(
        self,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        timestamp: Optional[datetime] = None,
    ) -> AuditEntry:
        """Append a new hash-chained entry to the JSONL ledger."""
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
            entry = AuditEntry(
                seq=next_seq,
                timestamp=ts,
                event_type=event_clean,
                actor=actor_clean,
                payload=normalized_payload,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            line = entry.model_dump_json() + "\n"
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def verify_chain(self) -> tuple[bool, Optional[str], int]:
        """Verify entire SHA-256 hash chain from genesis to tip.

        Returns `(valid, error_message, verified_entry_count)`.
        """
        with self._lock:
            if not self._path.exists():
                return True, None, 0

            expected_prev = GENESIS_HASH
            expected_seq = 1
            count = 0

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

                recomputed = _compute_entry_hash(
                    seq=entry.seq,
                    timestamp=entry.timestamp,
                    event_type=entry.event_type,
                    actor=entry.actor,
                    payload=entry.payload,
                    prev_hash=entry.prev_hash,
                )
                if entry.entry_hash != recomputed:
                    return (
                        False,
                        f"Entry hash tamper detected at seq {entry.seq} (line {line_no})",
                        count,
                    )

                expected_prev = entry.entry_hash
                expected_seq += 1
                count += 1

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

    def _get_tail_state(self) -> tuple[int, str]:
        if not self._path.exists():
            return 0, GENESIS_HASH
        size = self._path.stat().st_size
        if size == 0:
            return 0, GENESIS_HASH
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
                        return 0, GENESIS_HASH
                    last = AuditEntry.model_validate_json(lines[-1].decode("utf-8"))
                    return last.seq, last.entry_hash
        return 0, GENESIS_HASH
