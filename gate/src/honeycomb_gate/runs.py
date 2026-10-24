"""Run control: which runs are paused, and resuming one under human control (ADR-0002, 0007).

State lives in a small JSON file shared with the CLI. A paused run stays blocked until an
operator resumes it; resuming mints a fresh run id, so the identity that tripped stays
revoked for good.
"""

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from honeycomb_gate.locking import FileLock, read_json, write_json_atomic


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class RunControl:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = FileLock(path.with_name(path.name + ".lock"))

    def _read(self) -> dict[str, dict[str, Any]]:
        return read_json(self.path, {})

    def _write(self, data: dict[str, dict[str, Any]]) -> None:
        write_json_atomic(self.path, data, indent=2)

    def pause(self, run_id: str, reason: str, tool: str) -> None:
        with self._lock:
            data = self._read()
            if data.get(run_id, {}).get("status") == "paused":
                return  # keep the first record, including any resume request
            data[run_id] = {"status": "paused", "reason": reason, "tool": tool, "at": _now()}
            self._write(data)

    def resume_requested(self, run_id: str) -> bool:
        """Cheap check without taking the lock (the file is replaced atomically)."""
        entry = self._read().get(run_id)
        return bool(entry and entry["status"] == "paused" and "resume_requested_by" in entry)

    def inherit(
        self, new_run_id: str, also_paused: Iterable[str] = (), skip: Iterable[str] = ()
    ) -> list[str]:
        """A restarted gate must not forget a pause: retire paused runs and pause the new one.

        ``also_paused`` is for runs the log says are paused but this file has lost. ``skip`` is
        for runs that belong to someone else (token runs have their own revoked identity).
        """
        with self._lock:
            data = self._read()
            old = sorted(
                ({rid for rid, e in data.items() if e["status"] == "paused"} | set(also_paused))
                - set(skip)
            )
            if not old:
                return []
            for rid in old:
                data.setdefault(
                    rid, {"reason": "recovered from the log", "tool": "-", "at": _now()}
                )
                data[rid]["status"] = "revoked"
                data[rid]["superseded_by"] = new_run_id
            data[new_run_id] = {
                "status": "paused",
                "reason": "inherited_pause",
                "tool": "-",
                "at": _now(),
                "inherited_from": old,
            }
            self._write(data)
            return old

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._read().get(run_id)

    def paused(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {k: v for k, v in self._read().items() if v["status"] == "paused"}

    def request_resume(self, run_id: str, approver: str) -> str:
        """Ask for a paused run to be resumed. Returns ``ok``, ``unknown`` or ``not-paused``."""
        with self._lock:
            data = self._read()
            entry = data.get(run_id)
            if entry is None:
                return "unknown"
            if entry["status"] != "paused":
                return "not-paused"
            entry["resume_requested_by"] = approver
            entry["resume_requested_at"] = _now()
            self._write(data)
            return "ok"

    def take_resume(self, run_id: str, new_run_id: str) -> dict[str, Any] | None:
        """For the gate: if a resume was requested, retire the old id and say who asked."""
        with self._lock:
            data = self._read()
            entry = data.get(run_id)
            if not entry or entry["status"] != "paused" or "resume_requested_by" not in entry:
                return None
            entry["status"] = "revoked"
            entry["resumed_as"] = new_run_id
            self._write(data)
            return entry
