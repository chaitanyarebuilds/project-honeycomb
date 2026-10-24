"""Append-only, hash-chained event log with a SQLite query index (F2, ADR-0005).

The JSONL file is the source of truth. Every line carries ``prev_hash`` and ``hash`` so
that an edit, deletion or reordering is detectable with :func:`verify_chain`. High and
critical events are also copied to a second sink, and the chain head is checkpointed
there, so that truncating the main log is detectable too.
"""

import hashlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from honeycomb_gate.locking import FileLock, LockedError
from honeycomb_gate.redact import redact, sanitize_name

SCHEMA_VERSION = 1
GENESIS = "sha256:" + "0" * 64
_MAX_LINE_BYTES = 8192
_SEVERITIES = ["info", "low", "medium", "high", "critical"]


class LogCorruptError(RuntimeError):
    """The log cannot be appended to safely (for example a torn last line)."""


def _ulid_like() -> str:
    # 48-bit ms timestamp + 80 random bits, Crockford base32: sortable, ULID-shaped.
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    n = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10))
    return "".join(alphabet[(n >> (5 * i)) & 31] for i in range(25, -1, -1))


def new_run_id() -> str:
    return "run_" + _ulid_like()


def digest(payload: Any) -> str:
    """SHA-256 of the canonical JSON of the full, unredacted payload."""
    raw = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(event: dict[str, Any]) -> bytes:
    body = {k: v for k, v in event.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, default=str, separators=(",", ":")).encode()


def compute_hash(event: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(event)).hexdigest()


def severity_rank(severity: str) -> int:
    return _SEVERITIES.index(severity) if severity in _SEVERITIES else 0


class EventLog:
    def __init__(
        self,
        path: Path,
        *,
        run_id: str | None = None,
        agent_id: str = "default",
        alert_sink: Path | None = None,
        index: bool = True,
    ) -> None:
        self.path = path
        self.run_id = run_id or new_run_id()
        self.agent_id = agent_id
        self.alert_sink = alert_sink
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # One writer per log: a second gate on the same file would fork the hash chain.
        self._file_lock = FileLock(path.with_name(path.name + ".lock"))
        try:
            self._file_lock.acquire(blocking=False)
        except LockedError as exc:
            raise LogCorruptError(f"another gate is already writing {path}") from exc
        self._head, self._count = self._read_head()
        self._db: sqlite3.Connection | None = None
        if index:
            self._db = self._open_index(path.with_suffix(".sqlite3"))
        if alert_sink is not None:
            alert_sink.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _append_line(alert_sink, "")  # exists from now on, so a missing sink means tampering

    def _read_head(self) -> tuple[str, int]:
        if not self.path.exists():
            return GENESIS, 0
        head, count = GENESIS, 0
        with self.path.open(encoding="utf-8") as f:
            for number, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    head = json.loads(line)["hash"]
                except (json.JSONDecodeError, KeyError) as exc:
                    raise LogCorruptError(
                        f"{self.path} line {number} is damaged; run 'events verify' and keep the "
                        "file as evidence before starting a new log"
                    ) from exc
                count += 1
        return head, count

    def _open_index(self, db_path: Path) -> sqlite3.Connection:
        db = sqlite3.connect(db_path, check_same_thread=False)
        db.execute(
            "CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, event_id TEXT, ts TEXT,"
            " kind TEXT, severity TEXT, severity_rank INTEGER, run_id TEXT, agent_id TEXT,"
            " upstream TEXT, tool TEXT, decision TEXT, body TEXT)"
        )
        db.execute("CREATE INDEX IF NOT EXISTS ix_events_kind ON events(kind)")
        db.execute("CREATE INDEX IF NOT EXISTS ix_events_run ON events(run_id)")
        db.execute("CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts)")
        indexed = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if indexed != self._count:  # index missing or stale: rebuild from the JSONL source
            db.execute("DELETE FROM events")
            for seq, event in enumerate(read_events(self.path), start=1):
                self._insert(db, seq, event)
            db.commit()
        return db

    @staticmethod
    def _insert(db: sqlite3.Connection, seq: int, e: dict[str, Any]) -> None:
        db.execute(
            "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                seq,
                e["event_id"],
                e["ts"],
                e["kind"],
                e["severity"],
                severity_rank(e["severity"]),
                e.get("run_id"),
                e.get("agent_id"),
                e.get("upstream"),
                e.get("tool"),
                e.get("decision"),
                json.dumps(e),
            ),
        )

    def emit(self, kind: str, *, severity: str = "info", **fields: Any) -> dict[str, Any]:
        for name_field in ("tool", "upstream"):  # chosen by the agent: never trust their shape
            if name_field in fields and fields[name_field] is not None:
                fields[name_field] = sanitize_name(fields[name_field])
        if "args_redacted" in fields:
            fields["args_redacted"] = redact(fields["args_redacted"])
        if "details" in fields:
            fields["details"] = redact(fields["details"])
        with self._lock:
            event: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "event_id": _ulid_like(),
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "kind": kind,
                "severity": severity,
                "run_id": self.run_id,
                "agent_id": self.agent_id,
                **fields,
                "prev_hash": self._head,
            }
            if len(_canonical(event)) > _MAX_LINE_BYTES:
                event.pop("args_redacted", None)
                event["details"] = {"truncated": True}
            event["hash"] = compute_hash(event)
            _append_line(self.path, json.dumps(event, default=str))
            self._head = event["hash"]
            self._count += 1
            if self._db is not None:
                self._insert(self._db, self._count, event)
                self._db.commit()
            self._to_sink(event)
        return event

    def _to_sink(self, event: dict[str, Any]) -> None:
        if self.alert_sink is None:
            return
        # A checkpoint after every event means no event can be dropped from the tail of the main
        # log without the sink noticing. High and critical events are also copied in full.
        if severity_rank(event["severity"]) >= severity_rank("high"):
            _append_line(
                self.alert_sink, json.dumps({"type": "event", "event": event}, default=str)
            )
        _append_line(
            self.alert_sink,
            json.dumps({"type": "checkpoint", "count": self._count, "head": self._head}),
        )

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
        self._file_lock.release()


def _append_line(path: Path, line: str) -> None:
    """Append one line durably, creating the file readable only by its owner."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        if line:
            f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_events(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


@dataclass
class ChainReport:
    ok: bool
    events: int
    first_break: int | None = None  # 1-based line number
    reason: str = ""


def verify_chain(path: Path, checkpoints: Path | None = None) -> ChainReport:
    """Recompute the hash chain and, if given, check sink checkpoints against it."""
    prev = GENESIS
    heads: dict[int, str] = {}
    n = 0
    if not path.exists():
        if checkpoints is not None and checkpoints.exists() and _has_checkpoint(checkpoints):
            return ChainReport(False, 0, 1, "log file is missing but the second sink has records")
        return ChainReport(True, 0)
    if checkpoints is not None and not checkpoints.exists():
        return ChainReport(False, 0, 1, "second sink is configured but its file is missing")
    with path.open(encoding="utf-8") as f:
        for n, line in enumerate((ln for ln in f if ln.strip()), start=1):  # noqa: B007
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return ChainReport(False, n, n, "line is not valid JSON")
            if event.get("prev_hash") != prev:
                return ChainReport(False, n, n, "prev_hash does not match (line removed or moved)")
            if event.get("hash") != compute_hash(event):
                return ChainReport(False, n, n, "hash does not match (line edited)")
            prev = event["hash"]
            heads[n] = prev
    if checkpoints is not None and checkpoints.exists():
        with checkpoints.open(encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                if row.get("type") != "checkpoint":
                    continue
                if row["count"] > n:
                    return ChainReport(False, n, n + 1, "log is shorter than a recorded checkpoint")
                if heads.get(row["count"]) != row["head"]:
                    return ChainReport(False, n, row["count"], "checkpoint head does not match")
    return ChainReport(True, n)


def _has_checkpoint(path: Path) -> bool:
    with path.open(encoding="utf-8") as f:
        return any('"type": "checkpoint"' in line for line in f)


def query_events(
    db_path: Path,
    *,
    kind: str | None = None,
    min_severity: str | None = None,
    run_id: str | None = None,
    since: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    args: list[Any] = []
    if kind:
        clauses.append("kind LIKE ?")
        args.append(kind.replace("*", "%"))
    if min_severity:
        clauses.append("severity_rank >= ?")
        args.append(severity_rank(min_severity))
    if run_id:
        clauses.append("run_id = ?")
        args.append(run_id)
    if since:
        clauses.append("ts >= ?")
        args.append(since)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    db = sqlite3.connect(db_path)
    try:
        rows = db.execute(
            f"SELECT body FROM events{where} ORDER BY seq DESC LIMIT ?",  # noqa: S608
            [*args, limit],
        ).fetchall()
    finally:
        db.close()
    return [json.loads(r[0]) for r in reversed(rows)]
