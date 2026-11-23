"""Fail-closed persistent KillSwitch for the ClearFills Pre-Trade Risk Firewall."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ._locks import file_lock
from .models import utc_now


class KillSwitchState(BaseModel):
    """Persisted JSON state for the fail-closed kill switch."""

    model_config = ConfigDict(extra="forbid")

    tripped: bool = True
    reason: str = "Uninitialized kill-switch (fail-closed)"
    actor: str = "system"
    updated_at: datetime = Field(default_factory=utc_now)
    corrupt_or_missing: bool = False
    history: list[dict[str, Any]] = Field(default_factory=list)


class KillSwitch:
    """Fail-closed persistent kill switch backed by a JSON state file.

    Safety invariants:
    - Missing, unreadable, or corrupt JSON state ALWAYS evaluates as tripped (fail-closed).
    - `trip(reason, actor)` requires non-empty `reason` and `actor`.
    - `reset(reason, approver)` requires explicit non-empty `reason` and `approver`.
    - State writes are atomic (temp file in same directory + `os.replace`).
    """

    def __init__(self, state_path: str | Path) -> None:
        self._path = Path(state_path)
        self._lock = threading.Lock()

    @property
    def state_path(self) -> Path:
        return self._path

    def initialize_armed(self, actor: str = "system", reason: str = "Initial armed state") -> KillSwitchState:
        """Explicitly initialize an armed (non-tripped) kill-switch state file."""
        actor_clean = actor.strip()
        reason_clean = reason.strip()
        if not actor_clean or not reason_clean:
            raise ValueError("actor and reason must be non-empty")

        now = utc_now()
        state = KillSwitchState(
            tripped=False,
            reason=reason_clean,
            actor=actor_clean,
            updated_at=now,
            corrupt_or_missing=False,
            history=[
                {
                    "action": "INIT_ARMED",
                    "actor": actor_clean,
                    "reason": reason_clean,
                    "timestamp": now.isoformat(),
                }
            ],
        )
        with self._lock:
            self._write_atomic(state)
        return state

    def status(self) -> KillSwitchState:
        """Read current kill-switch state; fail-closed if missing or corrupt."""
        with self._lock:
            return self._read_fail_closed()

    def is_tripped(self) -> bool:
        """Return True if tripped OR if state file is missing/corrupt."""
        return self.status().tripped

    def trip(self, reason: str, actor: str) -> KillSwitchState:
        """Trip the kill switch, blocking all new exposure."""
        reason_clean = reason.strip()
        actor_clean = actor.strip()
        if not reason_clean:
            raise ValueError("trip() requires a non-empty reason")
        if not actor_clean:
            raise ValueError("trip() requires a non-empty actor")

        with self._lock, file_lock(self._path):
            current = self._read_fail_closed()
            history = list(current.history)
            now = utc_now()
            history.append(
                {
                    "action": "TRIP",
                    "actor": actor_clean,
                    "reason": reason_clean,
                    "timestamp": now.isoformat(),
                }
            )
            new_state = KillSwitchState(
                tripped=True,
                reason=reason_clean,
                actor=actor_clean,
                updated_at=now,
                corrupt_or_missing=False,
                history=history[-100:],
            )
            self._write_atomic(new_state)
            return new_state

    def reset(self, reason: str, approver: str) -> KillSwitchState:
        """Reset (arm) the kill switch. Requires explicit non-empty reason and approver."""
        reason_clean = reason.strip()
        approver_clean = approver.strip()
        if not reason_clean:
            raise ValueError("reset() requires an explicit non-empty reason")
        if not approver_clean:
            raise ValueError("reset() requires an explicit non-empty approver")

        with self._lock, file_lock(self._path):
            current = self._read_fail_closed()
            history = list(current.history)
            now = utc_now()
            history.append(
                {
                    "action": "RESET",
                    "approver": approver_clean,
                    "reason": reason_clean,
                    "timestamp": now.isoformat(),
                }
            )
            new_state = KillSwitchState(
                tripped=False,
                reason=reason_clean,
                actor=approver_clean,
                updated_at=now,
                corrupt_or_missing=False,
                history=history[-100:],
            )
            self._write_atomic(new_state)
            return new_state

    def _read_fail_closed(self) -> KillSwitchState:
        if not self._path.exists():
            return KillSwitchState(
                tripped=True,
                reason="FAIL_CLOSED: kill-switch state file is missing",
                actor="system",
                updated_at=utc_now(),
                corrupt_or_missing=True,
            )
        try:
            raw = self._path.read_text(encoding="utf-8")
            data = json.loads(raw)
            state = KillSwitchState.model_validate(data)
            return state
        except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
            return KillSwitchState(
                tripped=True,
                reason=f"FAIL_CLOSED: kill-switch state file is corrupt or unreadable ({type(exc).__name__})",
                actor="system",
                updated_at=utc_now(),
                corrupt_or_missing=True,
            )

    def _write_atomic(self, state: KillSwitchState) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = state.model_dump_json(indent=2)
        fd, tmp_name = tempfile.mkstemp(prefix=".ks_", suffix=".tmp", dir=str(self._path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self._path)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
